@echo off

if "%~1"=="" GOTO NO_ARGUMENTS
echo Compiling for: %1
call "%VCINSTALLDIR%Auxiliary\Build\vcvarsall.bat" %1
rc /v template.rc
cl /LD /GS- /DBUILDMODE=2 template.c /Fe:template_%1_windows.dll /link kernel32.lib template.res /entry:DllMain /subsystem:WINDOWS
cl /LD /GS- /DBUILDMODE=2 /DSCSIZE=262144 template.c /Fe:template_%1_windows.256kib.dll /link kernel32.lib template.res /entry:DllMain /subsystem:WINDOWS
exit /B

:NO_ARGUMENTS
%COMSPEC% /c "%0" x86
%COMSPEC% /c "%0" x64
del  *.obj *.res
move *.dll ..\..\..
