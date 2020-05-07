# Reflective DLL Project Template
This is a project template for Microsoft Visual Studio to aid in the creation
of Reflective DLLs based tools and exploits for the Metasploit Framework.

## Installation
To install the template, copy the template zip file to the Visual Studio
ProjectTemplates directory. The template zip file **does not** need to be
decompressed or extracted. For a default Visual Studio 2019 installation the
installation command would be:

```
copy "Reflective DLL.zip" "%USERPROFILE%\Documents\Visual Studio 2019\Templates\ProjectTemplates"
```

After the template has been copied, restart Visual Studio then:

1. Select "Create a new project"
1. Select "Reflective DLL" from the list of project templates
1. Name the project and set the location within the Metasploit Framework git
   working tree
    * For an exploit, this would likely be "CVE-20##-####" for the Project name
      and "external/source/exploits" for the Location.
    * For a general tool, this would likely be "external/source" for the
      Location.

Ensure that the [ReflectiveDLLInjection][1] submodule has been cloned and is up
to date with: `git submodule init; git submodule update`. This step only needs
to be done once to populate the necessary files for the build process.

<details>
<summary>Example Output</summary>

```
$ git submodule init
Submodule 'external/source/ReflectiveDLLInjection' (https://github.com/rapid7/ReflectiveDLLInjection.git) registered for path 'external/source/ReflectiveDLLInjection'
$ git submodule update
Cloning into '/metasploit-framework/external/source/ReflectiveDLLInjection'...
Submodule path 'external/source/ReflectiveDLLInjection': checked out '88e8e5f109793f09b35cb17a621f33647d644103'
```

</details>

## Build File Placement
It's important that the built binaries be placed in the `data` directory for use
by the framework. To copy the built binaries automatically:

1. Right click the project (usually the only child node of the tree) in the
   Solution Explorer and select "Properties".
1. Navigate to `Configuration Properties > Build Events > Post-Build Event`.
1. Set the "Command Line" value to a command that will copy the built binaries
   to a suitable subdirectory of `data`.

<details>
<summary>Command Line Example (Exploit)</summary>

Exploits are stored in subdirectories of `external/source/exploits` meaning they
need to traverse up four directories and copy their binaries to `data/exploits`.

```
IF EXIST "..\..\..\..\data\exploits\$(ProjectName)\" GOTO COPY
    mkdir "..\..\..\..\data\exploits\$(ProjectName)\"
:COPY
copy /y "$(TargetDir)$(TargetFileName)" "..\..\..\..\data\exploits\$(ProjectName)\"
```

</details>

## Template Updates
To update the template itself:

1. Open the `rdll_template.sln` file in Visual Studio
1. Make the desired changes
1. Go to `Project > Export Template...` and follow the wizard steps
1. Replace the zip file in this directory with the newly exported template

[1]: https://github.com/rapid7/ReflectiveDLLInjection
