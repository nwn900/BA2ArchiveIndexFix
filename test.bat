@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
cd /d "%~dp0"
if not exist build mkdir build
cl /nologo /MT /O2 /EHsc /std:c++17 tests\addrlib_test.cpp /Fo:build\ /Fe:build\addrlib_test.exe
