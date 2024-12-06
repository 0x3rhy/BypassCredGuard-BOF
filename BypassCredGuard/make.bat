@echo off
set BOFNAME="BypassCredGuard"
set PLAT="x86"
set STRIP="i686-w64-mingw32-strip"
IF "%Platform%"=="x64" set PLAT="x64"
IF "%Platform%"=="x64" set STRIP="x86_64-w64-mingw32-strip"

cl.exe /DBOF /nologo /Os /MT /W0 /GS- /c Source.cpp /Fo%BOFNAME%.%PLAT%.o
%STRIP% --strip-unneeded %BOFNAME%.%PLAT%.o
