@ECHO OFF
IF "%VCINSTALLDIR%" == "" GOTO NEED_VS

IF "%1"=="x86" GOTO BUILD_X86
IF "%1"=="X86" GOTO BUILD_X86
IF "%1"=="x64" GOTO BUILD_X64
IF "%1"=="X64" GOTO BUILD_X64

ECHO "Building Exploits x64 and x86 (Release)"
SET PLAT=all
GOTO RUN

:BUILD_X86
ECHO "Building Exploits x86 (Release)"
SET PLAT=x86
GOTO RUN

:BUILD_X64
ECHO "Building Exploits x64 (Release)"
SET PLAT=x64
GOTO RUN

:RUN
ECHO "Building Bypass UAC Injection"
msbuild.exe make.msbuild /target:%PLAT%


FOR /F "usebackq tokens=1,2 delims==" %%i IN (`wmic os get LocalDateTime /VALUE 2^>NUL`) DO IF '.%%i.'=='.LocalDateTime.' SET LDT=%%j
SET LDT=%LDT:~0,4%-%LDT:~4,2%-%LDT:~6,2% %LDT:~8,2%:%LDT:~10,2%:%LDT:~12,6%
echo Finished %ldt%

GOTO :END

:NEED_VS
ECHO "This command must be executed from within a Visual Studio Command prompt."
ECHO "This can be found under Microsoft Visual Studio 2013 -> Visual Studio Tools"

:END
