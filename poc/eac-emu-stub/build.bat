@echo off
rem --------------------------------------------------------------------
rem build.bat — build the EAC emulation stub DLL with MSVC
rem
rem Run from a "Developer Command Prompt for VS" so cl.exe is on PATH.
rem Output: EasyAntiCheat_x64.dll
rem --------------------------------------------------------------------

where cl.exe >nul 2>&1
if errorlevel 1 (
    echo.
    echo [!] cl.exe not found on PATH.
    echo [!] Run this from a "Developer Command Prompt for VS"
    echo [!] (installed with Visual Studio or Build Tools).
    exit /b 1
)

echo [*] Building EasyAntiCheat_x64.dll ...

cl /nologo /LD /O2 /W3 /DWIN32_LEAN_AND_MEAN ^
   eac_emu_stub.c ^
   /Fe:EasyAntiCheat_x64.dll ^
   /link /DEF:eac_emu_stub.def

if errorlevel 1 (
    echo [!] Build failed.
    exit /b 1
)

echo.
echo [*] Build complete.
echo     Output: EasyAntiCheat_x64.dll
echo     Lib:    EasyAntiCheat_x64.lib
echo     Exp:    EasyAntiCheat_x64.exp
echo.
echo [*] Verify exports:
dumpbin /nologo /exports EasyAntiCheat_x64.dll
