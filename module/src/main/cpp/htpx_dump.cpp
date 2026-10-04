#include "htpx_dump.h"

#include "log.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <sys/stat.h>

namespace {

struct MapEntry {
    uintptr_t start = 0;
    uintptr_t end = 0;
    uintptr_t file_offset = 0;
    std::string perms;
    std::string path;
};

static bool parse_maps(std::vector<MapEntry> &entries) {
    std::ifstream input("/proc/self/maps");
    if (!input) return false;

    std::string line;
    while (std::getline(input, line)) {
        const auto dash = line.find('-');
        const auto space = line.find(' ', dash == std::string::npos ? 0 : dash + 1);
        if (dash == std::string::npos || space == std::string::npos) continue;

        MapEntry entry;
        entry.start = static_cast<uintptr_t>(strtoull(line.substr(0, dash).c_str(), nullptr, 16));
        entry.end = static_cast<uintptr_t>(strtoull(line.substr(dash + 1, space - dash - 1).c_str(), nullptr, 16));

        std::stringstream fields(line.substr(space + 1));
        std::string offset;
        std::string device;
        std::string inode;
        fields >> entry.perms >> offset >> device >> inode;
        std::getline(fields, entry.path);
        while (!entry.path.empty() && entry.path.front() == ' ') entry.path.erase(entry.path.begin());
        entry.file_offset = static_cast<uintptr_t>(strtoull(offset.c_str(), nullptr, 16));

        if (entry.start < entry.end) entries.push_back(entry);
    }
    return !entries.empty();
}

static bool write_bytes(const std::string &path, const uint8_t *data, size_t size) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) return false;
    output.write(reinterpret_cast<const char *>(data), static_cast<std::streamsize>(size));
    return output.good();
}

static bool write_text(const std::string &path, const std::string &text) {
    std::ofstream output(path, std::ios::out | std::ios::trunc);
    if (!output) return false;
    output << text;
    return output.good();
}

static uint32_t read_u32(const uint8_t *base, size_t size, size_t offset) {
    if (offset > size || size - offset < sizeof(uint32_t)) return 0;
    uint32_t value = 0;
    memcpy(&value, base + offset, sizeof(value));
    return value;
}

static std::string read_string(const uint8_t *data, size_t size, uint32_t offset) {
    if (offset >= size) return {};
    const char *begin = reinterpret_cast<const char *>(data + offset);
    size_t length = 0;
    while (offset + length < size && begin[length] != '\0' && length < 4096) ++length;
    std::string value(begin, length);
    for (char &ch : value) {
        if (ch == '\r' || ch == '\n' || ch == '\t') ch = ' ';
        if (static_cast<unsigned char>(ch) < 0x20) ch = '_';
    }
    return value;
}

static std::string pseudo_identifier(const std::string &value, const char *fallback) {
    std::string result;
    result.reserve(value.size() + 1);
    for (const unsigned char ch : value) {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch == '_') {
            result.push_back(static_cast<char>(ch));
        } else {
            result.push_back('_');
        }
    }
    if (result.empty()) result = fallback;
    if (result[0] >= '0' && result[0] <= '9') result.insert(result.begin(), '_');
    return result;
}

struct HtpxField {
    std::string name;
    uint32_t type_index = 0;
    uint32_t token = 0;
};

struct HtpxMethod {
    std::string name;
    uint32_t token = 0;
    uint32_t flags = 0;
    uint32_t parameter_count = 0;
    std::vector<std::string> parameter_names;
};

static bool is_path(const MapEntry &entry, const char *needle) {
    return entry.path.find(needle) != std::string::npos;
}

static bool dump_metadata(const std::vector<MapEntry> &maps, const std::string &files) {
    const MapEntry *metadata = nullptr;
    for (const auto &entry : maps) {
        if (!is_path(entry, "global-metadata.dat") || entry.perms.empty() || entry.perms[0] != 'r') continue;
        if (entry.end - entry.start < 8) continue;
        const auto *bytes = reinterpret_cast<const uint8_t *>(entry.start);
        if (memcmp(bytes, "HTPX", 4) == 0) {
            metadata = &entry;
            break;
        }
    }
    if (!metadata) return false;

    const auto mapped_size = static_cast<size_t>(metadata->end - metadata->start);
    const auto *mapped = reinterpret_cast<const uint8_t *>(metadata->start);
    const uint32_t declared_size = read_u32(mapped, mapped_size, 4);
    const size_t size = declared_size >= 8 && declared_size <= mapped_size ? declared_size : mapped_size;
    if (size < 0xA8) return false;

    if (!write_bytes(files + "/global-metadata.decrypted.dat", mapped, size)) return false;

    std::ostringstream layout;
    layout << "container=HTPX\n";
    layout << "mapped_start=0x" << std::hex << metadata->start << "\n";
    layout << "mapped_end=0x" << metadata->end << "\n";
    layout << "declared_size=0x" << declared_size << "\n";
    layout << "header_payload_offset=0x8\n";
    layout << "string_offset=0x" << read_u32(mapped, size, 0x18) << "\n";
    layout << "string_size=0x" << read_u32(mapped, size, 0x1c) << "\n";
    layout << "type_definition_offset=0x" << read_u32(mapped, size, 0xa0) << "\n";
    layout << "type_definition_size=0x" << read_u32(mapped, size, 0xa4) << "\n";
    layout << "field_definition_offset=0x" << read_u32(mapped, size, 0x60) << "\n";
    layout << "field_definition_size=0x" << read_u32(mapped, size, 0x64) << "\n";
    layout << "method_definition_offset=0x" << read_u32(mapped, size, 0x30) << "\n";
    layout << "method_definition_size=0x" << read_u32(mapped, size, 0x34) << "\n";
    write_text(files + "/htpx_metadata_layout.txt", layout.str());

    // TypeDefinition records in this HTPX build are 0x58 bytes. The first two
    // fields retain the standard nameIndex/namespaceIndex layout, so this file
    // gives a useful class-name inventory even when public IL2CPP exports are gone.
    const uint32_t string_offset = read_u32(mapped, size, 0x18);
    const uint32_t type_offset = read_u32(mapped, size, 0xa0);
    const uint32_t type_size = read_u32(mapped, size, 0xa4);
    const uint32_t field_offset = read_u32(mapped, size, 0x60);
    const uint32_t field_size = read_u32(mapped, size, 0x64);
    const uint32_t method_offset = read_u32(mapped, size, 0x30);
    const uint32_t method_size = read_u32(mapped, size, 0x34);
    // v24 metadata: table pairs start at header+0x08, so pair k lives at 0x08+8k.
    // events=pair3@0x20 properties=pair4@0x28 parameters=pair10@0x58.
    const uint32_t event_offset = read_u32(mapped, size, 0x20);
    const uint32_t event_size = read_u32(mapped, size, 0x24);
    const uint32_t property_offset = read_u32(mapped, size, 0x28);
    const uint32_t property_size = read_u32(mapped, size, 0x2c);
    const uint32_t parameter_offset = read_u32(mapped, size, 0x58);
    const uint32_t parameter_size = read_u32(mapped, size, 0x5c);
    // Verified against table-size sums on this target:
    //   type record 0x58 = 16 ints + 8 u16 + bitfield + token
    //   ints: name(0x00) ns(0x04) byval(0x08) declaring(0x0c) parent(0x10) element(0x14)
    //         genericContainer(0x18) flags(0x1c) fieldStart(0x20) methodStart(0x24)
    //         eventStart(0x28) propertyStart(0x2c) nestedStart(0x30) interfacesStart(0x34)
    //         vtableStart(0x38) ifaceOffsetsStart(0x3c)
    //   u16 @0x40: method_count, property_count, field_count, event_count, ...
    //   field/method/parameter records are 12B; property/event records are 20B.
    constexpr size_t type_record_size = 0x58;
    constexpr size_t field_record_size = 0x0c;
    constexpr size_t method_record_size = 0x24;
    constexpr size_t property_record_size = 0x14;
    constexpr size_t event_record_size = 0x14;
    constexpr size_t parameter_record_size = 0x0c;
    std::ostringstream inventory;
    inventory << "// HTPX runtime metadata inventory\n";
    inventory << "// This target has stripped class-enumeration exports; names are read from the live metadata mapping.\n\n";
    std::vector<std::string> type_names;
    std::vector<std::string> type_namespaces;
    std::vector<std::vector<HtpxField>> fields_by_type;
    std::vector<std::vector<HtpxMethod>> methods_by_type;
    if (type_offset < size && type_size <= size - type_offset) {
        const size_t count = type_size / type_record_size;
        type_names.resize(count);
        type_namespaces.resize(count);
        fields_by_type.resize(count);
        methods_by_type.resize(count);
        for (size_t i = 0; i < count; ++i) {
            const size_t record = type_offset + i * type_record_size;
            const uint32_t name_index = read_u32(mapped, size, record);
            const uint32_t namespace_index = read_u32(mapped, size, record + 4);
            const std::string name = read_string(mapped, size, string_offset + name_index);
            const std::string namespaze = read_string(mapped, size, string_offset + namespace_index);
            if (name.empty()) continue;
            type_names[i] = name;
            type_namespaces[i] = namespaze;
            inventory << "// TypeIndex: " << i << "\n";
            inventory << "// Namespace: " << namespaze << "\n";
            inventory << "// Class: " << name << "\n\n";

            // Verified layout: fieldStart at record+0x20, methodStart at
            // record+0x24; u32@0x40 packs method_count(low)/property_count(high),
            // u32@0x44 packs field_count(low)/event_count(high).
            const uint32_t field_start = read_u32(mapped, size, record + 0x20);
            const uint32_t method_start = read_u32(mapped, size, record + 0x24);
            const uint32_t counts_mp = read_u32(mapped, size, record + 0x40);
            const uint32_t counts_fe = read_u32(mapped, size, record + 0x44);
            const uint32_t method_count = counts_mp & 0xffffU;
            const uint32_t property_count = (counts_mp >> 16) & 0xffffU;
            const uint32_t field_count = counts_fe & 0xffffU;
            const uint32_t event_count = (counts_fe >> 16) & 0xffffU;
            const size_t field_capacity = field_size / field_record_size;
            const size_t method_capacity = method_size / method_record_size;
            const size_t property_capacity = property_size / property_record_size;
            const size_t event_capacity = event_size / event_record_size;
            const size_t parameter_capacity = parameter_size / parameter_record_size;
            if (field_start != 0xffffffffU && field_offset < size &&
                field_size <= size - field_offset &&
                field_start <= field_capacity &&
                field_count <= field_capacity - field_start) {
                for (uint32_t field = 0; field < field_count; ++field) {
                    const size_t field_record = field_offset +
                                                static_cast<size_t>(field_start + field) * field_record_size;
                    const uint32_t field_name = read_u32(mapped, size, field_record);
                    const uint32_t field_type = read_u32(mapped, size, field_record + 4);
                    const uint32_t field_token = read_u32(mapped, size, field_record + 8);
                    HtpxField field_info;
                    field_info.name = read_string(mapped, size, string_offset + field_name);
                    field_info.type_index = field_type;
                    field_info.token = field_token;
                    fields_by_type[i].push_back(field_info);
                    inventory << "//   Field: " << field_info.name
                         << " (typeIndex=0x" << std::hex << field_type
                         << ", token=0x" << field_token << std::dec << ")\n";
                }
                inventory << "\n";
            }
            if (property_count > 0 && property_offset < size &&
                property_size <= size - property_offset) {
                const uint32_t property_start = read_u32(mapped, size, record + 0x2c);
                if (property_start != 0xffffffffU && property_start <= property_capacity &&
                    property_count <= property_capacity - property_start) {
                    for (uint32_t prop = 0; prop < property_count; ++prop) {
                        const size_t property_record = property_offset +
                                                       static_cast<size_t>(property_start + prop) * property_record_size;
                        const uint32_t prop_name = read_u32(mapped, size, property_record);
                        const uint32_t prop_get = read_u32(mapped, size, property_record + 4);
                        const uint32_t prop_set = read_u32(mapped, size, property_record + 8);
                        inventory << "//   Property: " << read_string(mapped, size, string_offset + prop_name)
                             << " (get=0x" << std::hex << prop_get << ", set=0x" << prop_set << std::dec << ")\n";
                    }
                }
            }
            if (event_count > 0 && event_offset < size &&
                event_size <= size - event_offset) {
                const uint32_t event_start = read_u32(mapped, size, record + 0x28);
                if (event_start != 0xffffffffU && event_start <= event_capacity &&
                    event_count <= event_capacity - event_start) {
                    for (uint32_t evt = 0; evt < event_count; ++evt) {
                        const size_t event_record = event_offset +
                                                    static_cast<size_t>(event_start + evt) * event_record_size;
                        const uint32_t evt_name = read_u32(mapped, size, event_record);
                        inventory << "//   Event: " << read_string(mapped, size, string_offset + evt_name) << "\n";
                    }
                }
            }
            // Methods: iterate via the type's own methodStart/method_count.
            if (method_start != 0xffffffffU && method_offset < size &&
                method_size <= size - method_offset &&
                method_start <= method_capacity &&
                method_count <= method_capacity - method_start) {
                for (uint32_t m = 0; m < method_count; ++m) {
                    const size_t method_record = method_offset +
                                                 static_cast<size_t>(method_start + m) * method_record_size;
                    const uint32_t method_name_index = read_u32(mapped, size, method_record);
                    const uint32_t token = read_u32(mapped, size, method_record + 0x18);
                    const uint32_t flags = read_u32(mapped, size, method_record + 0x1c);
                    const uint32_t parameter_start = read_u32(mapped, size, method_record + 0x10);
                    const uint32_t packed_param = read_u32(mapped, size, method_record + 0x20);
                    const uint32_t parameter_count = (packed_param >> 16) & 0xffffU;
                    HtpxMethod method_info;
                    method_info.name = read_string(mapped, size, string_offset + method_name_index);
                    method_info.token = token;
                    method_info.flags = flags;
                    method_info.parameter_count = parameter_count;
                    if (parameter_count > 0 && parameter_start != 0xffffffffU &&
                        parameter_offset < size && parameter_size <= size - parameter_offset &&
                        parameter_start <= parameter_capacity &&
                        parameter_count <= parameter_capacity - parameter_start) {
                        for (uint32_t p = 0; p < parameter_count; ++p) {
                            const size_t parameter_record = parameter_offset +
                                                            static_cast<size_t>(parameter_start + p) * parameter_record_size;
                            const uint32_t param_name = read_u32(mapped, size, parameter_record);
                            method_info.parameter_names.push_back(
                                read_string(mapped, size, string_offset + param_name));
                        }
                    }
                    methods_by_type[i].push_back(method_info);
                    inventory << "//   Method: " << method_info.name
                         << " params=" << parameter_count
                         << " token=0x" << std::hex << token
                         << " flags=0x" << flags << std::dec << "\n";
                }
            }
        }
    }

    // Methods are already attributed per type via methodStart/method_count
    // above, which matches the metadata table sums exactly; no second global
    // scan is needed.

    // Keep the lossless metadata view separate from dump.cs. The latter is a
    // readable pseudo-C# layout; unknown type names, parameters and RVAs are
    // marked instead of being guessed from stripped exports.
    std::ostringstream dump;
    dump << "// HTPX metadata dump (pseudo-C#)\n";
    dump << "// This is not compilable source: the target strips IL2CPP class/method exports.\n";
    dump << "// Field/return/parameter types and RVAs are intentionally marked unknown.\n\n";
    for (size_t i = 0; i < type_names.size(); ++i) {
        if (type_names[i].empty()) continue;
        dump << "// TypeIndex: " << i << "\n";
        dump << "// Original Namespace: " << type_namespaces[i] << "\n";
        dump << "// Original Class: " << type_names[i] << "\n";
        dump << "class " << pseudo_identifier(type_names[i], "Type") << "\n{\n";
        if (!fields_by_type[i].empty()) {
            dump << "    // Fields (type metadata is unresolved)\n";
            for (const auto &field : fields_by_type[i]) {
                dump << "    // token=0x" << std::hex << field.token
                     << " typeIndex=0x" << field.type_index << std::dec << "\n";
                dump << "    private object " << pseudo_identifier(field.name, "field") << ";\n";
            }
        }
        if (!methods_by_type[i].empty()) {
            dump << "    // Methods (RVA and return type are unavailable)\n";
            for (const auto &method : methods_by_type[i]) {
                dump << "    // token=0x" << std::hex << method.token
                     << " flags=0x" << method.flags << std::dec
                     << " params=" << method.parameter_count << "\n";
                dump << "    private object " << pseudo_identifier(method.name, "Method") << "(";
                if (!method.parameter_names.empty()) {
                    for (size_t p = 0; p < method.parameter_names.size(); ++p) {
                        if (p) dump << ", ";
                        dump << "object " << pseudo_identifier(method.parameter_names[p], "arg");
                    }
                } else if (method.parameter_count > 0) {
                    dump << "/* " << method.parameter_count << " parameters */";
                }
                dump << ");\n";
            }
        }
        dump << "}\n\n";
    }
    write_text(files + "/dump.cs", dump.str());
    write_text(files + "/htpx_metadata_inventory.txt", inventory.str());
    return true;
}

static bool dump_library(const std::vector<MapEntry> &maps, const std::string &files) {
    const MapEntry *base_map = nullptr;
    uintptr_t library_end = 0;
    std::string library_path;
    for (const auto &entry : maps) {
        if (!is_path(entry, "/libil2cpp.so")) continue;
        if (library_path.empty()) library_path = entry.path;
        if (entry.path != library_path) continue;
        library_end = std::max(library_end, entry.end);
        if (entry.file_offset == 0 && (!base_map || entry.start < base_map->start)) base_map = &entry;
    }
    if (!base_map || library_end <= base_map->start || library_path.empty()) return false;

    const uintptr_t base = base_map->start;
    const size_t flat_size = static_cast<size_t>(library_end - base);
    std::vector<uint8_t> flat(flat_size, 0);
    for (const auto &entry : maps) {
        if (entry.path != library_path || entry.start < base || entry.end > library_end) continue;
        const size_t offset = static_cast<size_t>(entry.start - base);
        const size_t length = static_cast<size_t>(entry.end - entry.start);
        memcpy(flat.data() + offset, reinterpret_cast<const void *>(entry.start), length);
    }
    if (!write_bytes(files + "/libil2cpp.runtime.flat.bin", flat.data(), flat.size())) return false;

    std::ifstream input(library_path, std::ios::binary);
    if (!input) return true;
    input.seekg(0, std::ios::end);
    const auto disk_size = static_cast<size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    std::vector<uint8_t> library(disk_size);
    input.read(reinterpret_cast<char *>(library.data()), static_cast<std::streamsize>(library.size()));
    if (!input.good() && !input.eof()) return true;

#if __LP64__
    if (library.size() >= sizeof(Elf64_Ehdr)) {
        auto *header = reinterpret_cast<const Elf64_Ehdr *>(library.data());
        if (memcmp(header->e_ident, ELFMAG, SELFMAG) == 0 &&
            header->e_ident[EI_CLASS] == ELFCLASS64 &&
            header->e_phentsize == sizeof(Elf64_Phdr)) {
            for (uint16_t i = 0; i < header->e_phnum; ++i) {
                const size_t ph_offset = header->e_phoff + static_cast<size_t>(i) * header->e_phentsize;
                if (ph_offset > library.size() || library.size() - ph_offset < sizeof(Elf64_Phdr)) continue;
                const auto *ph = reinterpret_cast<const Elf64_Phdr *>(library.data() + ph_offset);
                if (ph->p_type != PT_LOAD || ph->p_offset > library.size() || ph->p_filesz > library.size() - ph->p_offset) continue;
                if (ph->p_vaddr >= flat.size() || ph->p_filesz > flat.size() - ph->p_vaddr) continue;
                memcpy(library.data() + ph->p_offset, flat.data() + ph->p_vaddr, static_cast<size_t>(ph->p_filesz));
            }
        }
    }
#endif
    write_bytes(files + "/libil2cpp.runtime.reconstructed.so", library.data(), library.size());
    return true;
}

} // namespace

bool htpx_dump(const char *game_data_dir) {
    if (!game_data_dir) return false;
    const std::string root(game_data_dir);
    const std::string files = root + "/files";
    mkdir(root.c_str(), 0700);
    mkdir(files.c_str(), 0700);

    std::vector<MapEntry> maps;
    if (!parse_maps(maps)) {
        LOGW("HTPX: unable to read /proc/self/maps");
        return false;
    }
    const bool metadata_ok = dump_metadata(maps, files);
    if (!metadata_ok) return false;
    const bool library_ok = dump_library(maps, files);
    if (metadata_ok) LOGI("HTPX: decrypted metadata written to %s", files.c_str());
    if (library_ok) LOGI("HTPX: runtime libil2cpp reconstruction written to %s", files.c_str());
    return metadata_ok;
}
