# PE Source Code
This directory contains the source code for the PE executable templates.

## Building
Use the provided `build_all.ps1` script from within the Visual Studio developer
console. The script requires that the `%VCINSTALLDIR%` environment variable be
defined (which it should be by default). By default it builds all templates for
both x86 and x64, then moves the outputs into the correct folder.

```powershell
# build everything
.\build_all.ps1

# build only x86
.\build_all.ps1 -Architectures x86

# build only EXE templates
.\build_all.ps1 -Templates exe,exe_service
```
