@echo off

if "%~1"=="" GOTO NO_ARGUMENTS
echo Compiling for: %1
call "%VCINSTALLDIR%Auxiliary\Build\vcvarsall.bat" %1
cl /CLR /LD /GS- /I ..\dll /DBUILDMODE=2 template.cpp /Fe:template_%1_windows_mixed_mode.dll /link mscoree.lib kernel32.lib /entry:DllMain /subsystem:WINDOWS
cl /CLR /LD /GS- /I ..\dll /DBUILDMODE=2 /DSCSIZE=262144 template.cpp /Fe:template_%1_windows_mixed_mode.256kib.dll /link mscoree.lib kernel32.lib /entry:DllMain /subsystem:WINDOWS
exit /B

:NO_ARGUMENTS
%COMSPEC% /c "%0" x86
%COMSPEC% /c "%0" x64
del  *.obj
move *.dll ..\..\..
