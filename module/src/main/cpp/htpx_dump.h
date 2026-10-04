#pragma once

#include <cstddef>

// Extracts the decrypted HTPX metadata mapping and rebuilds a live libil2cpp
// ELF from the pages currently readable in this process.
bool htpx_dump(const char *game_data_dir);
