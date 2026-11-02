@echo off
setlocal
cd /d "%~dp0" || exit /b 1

where cl >nul 2>&1
if not errorlevel 1 goto compiler_ready
set "FREEZEFIX_VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%FREEZEFIX_VSWHERE%" (
    echo ERROR: Install Visual Studio C++ Build Tools, or run from an x64 Native Tools prompt.
    exit /b 1
)
for /f "usebackq tokens=*" %%I in (`"%FREEZEFIX_VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "FREEZEFIX_VSROOT=%%I"
if not defined FREEZEFIX_VSROOT (
    echo ERROR: No Visual Studio installation with C++ tools was found.
    exit /b 1
)
call "%FREEZEFIX_VSROOT%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1

:compiler_ready
if not exist build mkdir build
if not exist build exit /b 1
cl /nologo /LD /MT /O2 /std:c++17 /EHsc /W4 /DWIN32_LEAN_AND_MEAN /DNOMINMAX ^
   /I"third_party" /I"third_party\minhook\src" ^
   src\main.cpp ^
   third_party\minhook\src\buffer.c third_party\minhook\src\hook.c ^
   third_party\minhook\src\trampoline.c third_party\minhook\src\hde\hde64.c ^
   /Fo:build\ /Fe:build\FreezeFixF4.dll ^
   /link /MACHINE:X64 /PDB:build\FreezeFixF4.pdb bcrypt.lib
exit /b %errorlevel%
