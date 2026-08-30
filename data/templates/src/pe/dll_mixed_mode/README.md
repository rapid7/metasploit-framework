# DLL Mixed Mode
This is a [Mixed Mode Assembly][1], it allows a native payload from Metasploit
to be executed from within what is the bare minimum requirements of a valid .NET
assembly. The DLL source code is the same as the [standard DLL][2] template, the
primary difference from a file perspective is that this DLL has the necessary
manifest information to be loaded as a managed assembly.

## Building
Use the provided `build.bat` file, and run it from within the Visual Studio
developer console. The batch file requires that the `%VCINSTALLDIR%` environment
variable be defined (which it should be by default). The build script will
create both the x86 and x64 templates before moving them into the correct
folder. The current working directory when the build is run must be the source
code directory (`dll_mixed_mode`).

## References

* https://github.com/bao7uo/MixedUp
* https://thewover.github.io/Mixed-Assemblies/


[1]: https://docs.microsoft.com/en-us/cpp/dotnet/mixed-native-and-managed-assemblies?view=vs-2019
[2]: https://github.com/rapid7/metasploit-framework/tree/master/data/templates/src/pe/dlli
