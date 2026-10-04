@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem ============================================================
rem  Zygisk-Il2CppDumper - Windows Build Script
rem
rem  Compiles the module with Gradle and produces the flashable
rem  Magisk module zip under the "out" directory.
rem
rem  Why subst? ninja uses the ANSI Win32 API to open files, which
rem  fails on non-ASCII project paths. Mapping the project to a
rem  pure-ASCII drive letter sidesteps this cleanly.
rem
rem  Usage:
rem    build.bat                 (auto-detect NDK from SDK\ndk)
rem    build.bat 23.2.8568313    (force a specific NDK version)
rem
rem  Optional environment overrides:
rem    JDK17              -> path to a JDK 11-17 (required by AGP 7.4.2)
rem    ANDROID_SDK_ROOT   -> path to the Android SDK
rem    NDK_VERSION        -> NDK version string (same as the folder name)
rem ============================================================

title Zygisk-Il2CppDumper Build

echo.
echo ============================================================
echo   Zygisk-Il2CppDumper - Build
echo ============================================================
echo.

rem ============================================================
rem  1) JDK 17  (AGP 7.4.2 requires JDK 11-17)
rem ============================================================
if "%JDK17%"=="" set "JDK17=C:\Users\52334\.jdks\jbr-17.0.14"
if not exist "%JDK17%\bin\java.exe" (
    echo [ERROR] JDK 17 not found at: "%JDK17%"
    echo         Set the JDK17 environment variable to a valid JDK 11-17 path.
    exit /b 1
)
set "JAVA_HOME=%JDK17%"
set "PATH=%JAVA_HOME%\bin;%PATH%"
echo [ 1/6 ] JDK   : %JAVA_HOME%

rem ============================================================
rem  2) Android SDK
rem ============================================================
if "%ANDROID_SDK_ROOT%"=="" set "ANDROID_SDK_ROOT=C:\Users\52334\AppData\Local\Android\Sdk"
if not exist "%ANDROID_SDK_ROOT%\platforms" (
    echo [ERROR] Android SDK not found at: "%ANDROID_SDK_ROOT%"
    echo         Set ANDROID_SDK_ROOT to your SDK path.
    exit /b 1
)
rem Export both (AGP reads ANDROID_SDK_ROOT and legacy ANDROID_HOME)
set "ANDROID_HOME=%ANDROID_SDK_ROOT%"
echo [ 2/6 ] SDK   : %ANDROID_SDK_ROOT%

rem ============================================================
rem  3) NDK version  (from arg, env, or auto-detect SDK\ndk)
rem ============================================================
if not "%~1"=="" set "NDK_VERSION=%~1"

if "%NDK_VERSION%"=="" (
    if exist "%ANDROID_SDK_ROOT%\ndk" (
        for /f "delims=" %%D in ('dir /b /ad "%ANDROID_SDK_ROOT%\ndk" 2^>nul') do (
            if "!NDK_VERSION!"=="" set "NDK_VERSION=%%D"
        )
    )
)

if "%NDK_VERSION%"=="" (
    echo [ERROR] No NDK found under "%ANDROID_SDK_ROOT%\ndk"
    echo         Install an NDK or pass its version as an argument,
    echo         e.g.  build.bat 23.2.8568313
    exit /b 1
)
echo [ 3/6 ] NDK   : %NDK_VERSION%

rem ============================================================
rem  4) Map the project's PARENT folder to a pure-ASCII drive
rem     letter, then cd into the project. Mapping the project
rem     dir itself makes it the drive root (empty project name),
rem     so we map the parent and step into the ASCII project
rem     folder "Zygisk-Il2CppDumper".
rem ============================================================
echo [ 4/6 ] Mapping project parent to an ASCII drive...
set "SCRIPT_DIR=%~dp0"
rem Parent dir (one level up)
for %%I in ("%SCRIPT_DIR%..") do set "PARENT_DIR=%%~fI"
rem Project folder name (last segment, pure ASCII)
for %%I in ("%SCRIPT_DIR%.") do set "PROJ_NAME=%%~nxI"

set "BUILD_DRIVE="
for %%L in (Z Y X W V U T) do (
    if not defined BUILD_DRIVE (
        subst %%L: "%PARENT_DIR%" >nul 2>&1
        if not errorlevel 1 set "BUILD_DRIVE=%%L:"
    )
)
if not defined BUILD_DRIVE (
    echo [ERROR] Could not map the project parent to an ASCII drive letter.
    exit /b 1
)
cd /d "%BUILD_DRIVE%\%PROJ_NAME%"
echo          -> %BUILD_DRIVE%\%PROJ_NAME%  ^(= %PARENT_DIR% ^)

rem ============================================================
rem  5) Prepare project config
rem     - write local.properties (sdk.dir)
rem     - patch ndkVersion in module\build.gradle
rem     - ensure android.overridePathCheck=true (non-ASCII path)
rem ============================================================
echo [ 5/6 ] Preparing project config...

set "SDK_FORWARD=%ANDROID_SDK_ROOT:\=/%"
> "local.properties" echo sdk.dir=%SDK_FORWARD%

powershell -NoProfile -Command "$f='module\build.gradle'; $c=[IO.File]::ReadAllText($f); $c=$c -replace 'ndkVersion\s+''[^'']*''','ndkVersion ''%NDK_VERSION%'''; [IO.File]::WriteAllText($f,$c)"

findstr /c:"android.overridePathCheck" "gradle.properties" >nul 2>&1
if errorlevel 1 (
    echo android.overridePathCheck=true>> "gradle.properties"
    echo          -> Added android.overridePathCheck=true to gradle.properties
)

rem ============================================================
rem  6) Build
rem ============================================================
echo [ 6/6 ] Building (first run may take a while)...
echo.
call gradlew.bat :module:assembleRelease --no-daemon
set "BUILD_RESULT=%ERRORLEVEL%"

rem Always remove the temporary drive mapping
subst "%BUILD_DRIVE%" /d >nul 2>&1

if not "%BUILD_RESULT%"=="0" (
    echo.
    echo [ERROR] Build failed. See output above.
    exit /b 1
)

rem ============================================================
rem  Show output
rem ============================================================
echo.
echo Build completed successfully.
echo.
echo Output:
for %%Z in ("%SCRIPT_DIR%out\zygisk-il2cppdumper-*.zip") do echo   %%~fZ
echo.
echo Done. Flash the zip in Magisk to use the module.
echo.

endlocal
