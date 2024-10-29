@echo off

if "%~1"=="" GOTO NO_ARGUMENTS
echo Compiling for: %1
call "%VCINSTALLDIR%Auxiliary\Build\vcvarsall.bat" %1
rc /v /fo template.res ../dll/template.rc
cl /LD /GS- /DBUILDMODE=2 /I . /FI exports.h ../dll/template.c /Fe:template_%1_windows_dccw_gdiplus.dll /link kernel32.lib template.res /entry:DllMain /subsystem:WINDOWS
cl /LD /GS- /DBUILDMODE=2 /DSCSIZE=262144 /I . /FI exports.h ../dll/template.c /Fe:template_%1_windows_dccw_gdiplus.256kib.dll /link kernel32.lib template.res /entry:DllMain /subsystem:WINDOWS
exit /B

:NO_ARGUMENTS
%COMSPEC% /c "%0" x86
%COMSPEC% /c "%0" x64
del  *.exp *.lib *.res *.obj
move *.dll ..\..\..
