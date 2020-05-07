# Reflective DLL Project Template
This is a project template for Microsoft's Visual Studio to aid in the creation
of Reflective DLLs.

## Installation
To install the template, copy the template file to the Visual Studio templates
directory. For a default Visual Studio 2019 installation the command would be:

```
copy "Reflective DLL.zip" "%USERPROFILE%\Documents\Visual Studio 2019\Templates\ProjectTemplates"
```

After the template has been copied, restart Visual Studio and select "Reflective
DLL" from the available project templates.

Ensure that the [ReflectiveDLLInjection][1] submodule has been cloned and is up
to date with: `git init submodule; git submodule update`.

## Template Updates
To update the template itself:

1. Open the `rdll_template.sln` file in Visual Studio
1. Make the desired changes
1. Go to `Project > Export Template...` and follow the wizard steps
1. Replace the zip file in this directory with the newly exported template

[1]: https://github.com/rapid7/ReflectiveDLLInjection
