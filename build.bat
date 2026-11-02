@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
if not exist build mkdir build
cd /d "%~dp0"
cl /nologo /LD /MT /O2 /std:c++17 /EHsc /W3 ^
   /I"third_party" /I"third_party\minhook\src" ^
   src\main.cpp ^
   third_party\minhook\src\buffer.c third_party\minhook\src\hook.c ^
   third_party\minhook\src\trampoline.c third_party\minhook\src\hde\hde64.c ^
   /Fo:build\ /Fe:build\FreezeFixF4.dll ^
   /link /PDB:build\FreezeFixF4.pdb
