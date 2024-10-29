# PE Source Code
This directory contains the source code for the PE executable templates.

## Building DLLs
Use the provided `build_dlls.bat` file, and run it from within the Visual Studio
developer console. The batch file requires that the `%VCINSTALLDIR%` environment
variable be defined (which it should be by default). The build script will
create both the x86 and x64 templates before moving them into the correct
folder. The current working directory when the build is run must be the source
code directory (`pe`).
