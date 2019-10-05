@ECHO OFF
IF "%VCINSTALLDIR%" == "" GOTO NEED_VS

IF "%1"=="x86" GOTO BUILD_X86
IF "%1"=="X64" GOTO BUILD_X64

ECHO "Building HostingCLR x64 and x86 (Release)"
SET PLAT=all
GOTO RUN

:BUILD_X86
ECHO "Building HostingCLR x86 (Release)"
SET PLAT=x86
GOTO RUN

:BUILD_X64
ECHO "Building HostingCLR x64 (Release)"
SET PLAT=x64
GOTO RUN

:RUN
PUSHD workspace
msbuild.exe make.msbuild /target:%PLAT%
POPD

GOTO :END

:NEED_VS
ECHO "This command must be executed from within a Visual Studio Command prompt."
ECHO "This can be found under Microsoft Visual Studio 2017 -> Visual Studio Tools"

:END