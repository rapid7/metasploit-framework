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

# build the AArch64 DLL from the shared dll/template.c
.\build_all.ps1 -Architectures aarch64 -Templates dll
```

The AArch64 EXE is still a dedicated source file. Compile it with MSVC on a
Windows ARM64 host using the instructions at the top of
`exe/template_aarch64_windows.c`.
