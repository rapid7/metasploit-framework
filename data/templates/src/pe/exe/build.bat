@echo off

if "%~1"=="" GOTO NO_ARGUMENTS
echo Compiling for: %1
call "%VCINSTALLDIR%Auxiliary\Build\vcvarsall.bat" %1
cl /GS- template.c /Fe:template_%1_windows.exe /link kernel32.lib /entry:main /subsystem:WINDOWS /NODEFAULTLIB
cl /GS- /DSCSIZE=262144 template.c /Fe:template_%1_windows.256kib.exe /link kernel32.lib /entry:main /subsystem:WINDOWS /NODEFAULTLIB
exit /B

:NO_ARGUMENTS
%COMSPEC% /c "%0" x86
%COMSPEC% /c "%0" x64
del  *.obj *.res
move *.exe ..\..\..
