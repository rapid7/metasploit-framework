<#
.SYNOPSIS
    Build all PE executable and DLL templates for Metasploit.

.DESCRIPTION
    Compiles x86 and x64 variants of the EXE, service EXE, DLL, GDI+ DLL, and
    mixed-mode DLL templates using the MSVC toolchain. After linking, the EXE
    templates are patched to lower the minimum subsystem version so they can run
    on legacy Windows (NT 4.0+ for x86, Server 2003+ for x64). Modern MSVC
    linkers enforce a floor of 5.01/5.02 which is too high for those targets.

.PARAMETER Architectures
    Which architectures to build. Defaults to both x86 and x64.

.PARAMETER Templates
    Which templates to build. Defaults to all of them.

.EXAMPLE
    .\build_all.ps1
    .\build_all.ps1 -Architectures x86
    .\build_all.ps1 -Templates exe,exe_service
#>

param(
    [ValidateSet('x86', 'x64')]
    [string[]]$Architectures = @('x86', 'x64'),

    [ValidateSet('exe', 'exe_service', 'dll', 'dll_gdiplus', 'dll_mixed_mode')]
    [string[]]$Templates = @('exe', 'exe_service', 'dll', 'dll_gdiplus', 'dll_mixed_mode')
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutputDir = Resolve-Path (Join-Path $ScriptDir '..\..')

# Each entry defines only what varies per template. The build function handles
# the common logic: calling cl, optional 256KiB variant, PE version patching.
#
#   Dir          - subdirectory containing the source
#   OutputFmt    - output filename format string, {0} is replaced with the architecture
#   Source       - source file passed to cl
#   ClFlags      - flags passed to cl (before /link)
#   LinkLibs     - libraries passed to the linker (after /link)
#   LinkRes      - optional .res file to link
#   EntryPoint   - /entry value
#   NoDefaultLib - if set, pass /NODEFAULTLIB to the linker
#   RcArgs       - optional resource compiler arguments (run before cl)
#   PatchVersion - if set, patch the PE subsystem version after linking
#
# DLL templates automatically get a 256KiB payload variant built alongside the
# standard size. This is determined by the output extension, not a per-template flag.
$BuildDefs = [ordered]@{
    exe = @{
        Dir          = 'exe'
        OutputFmt    = 'template_{0}_windows.exe'
        Source       = 'template.c'
        ClFlags      = @('/GS-')
        LinkLibs     = @('kernel32.lib')
        EntryPoint   = 'main'
        NoDefaultLib = $true
        PatchVersion = $true
    }
    exe_service = @{
        Dir          = 'exe_service'
        OutputFmt    = 'template_{0}_windows_svc.exe'
        Source       = 'template.c'
        ClFlags      = @('/GS-', '/DBUILDMODE=2')
        LinkLibs     = @('advapi32.lib', 'kernel32.lib')
        EntryPoint   = 'main'
        NoDefaultLib = $true
        PatchVersion = $true
    }
    dll = @{
        Dir          = 'dll'
        OutputFmt    = 'template_{0}_windows.dll'
        Source       = 'template.c'
        ClFlags      = @('/LD', '/GS-', '/DBUILDMODE=2')
        LinkLibs     = @('kernel32.lib')
        LinkRes      = 'template.res'
        EntryPoint   = 'DllMain'
        RcArgs       = @('/v', 'template.rc')
    }
    dll_gdiplus = @{
        Dir          = 'dll_gdiplus'
        OutputFmt    = 'template_{0}_windows_dccw_gdiplus.dll'
        Source       = '../dll/template.c'
        ClFlags      = @('/LD', '/GS-', '/DBUILDMODE=2', '/I', '.', '/FI', 'exports.h')
        LinkLibs     = @('kernel32.lib')
        LinkRes      = 'template.res'
        EntryPoint   = 'DllMain'
        RcArgs       = @('/v', '/fo', 'template.res', '../dll/template.rc')
    }
    dll_mixed_mode = @{
        Dir          = 'dll_mixed_mode'
        OutputFmt    = 'template_{0}_windows_mixed_mode.dll'
        Source       = 'template.cpp'
        ClFlags      = @('/CLR', '/LD', '/GS-', '/I', '..\dll', '/DBUILDMODE=2')
        LinkLibs     = @('mscoree.lib', 'kernel32.lib')
        EntryPoint   = 'DllMain'
    }
}

if (-not $env:VCINSTALLDIR) {
    Write-Error 'VCINSTALLDIR is not set. Run this script from a Visual Studio Developer Command Prompt.'
    exit 1
}

function Invoke-VCVars {
    param([string]$Arch)
    # vcvarsall.bat no-ops if VSCMD_VER is already set, so clear its state
    # flags before re-running. Otherwise the second arch silently inherits
    # the first arch's toolchain and produces wrong-architecture binaries.
    foreach ($v in 'VSCMD_VER', 'VSCMD_ARG_TGT_ARCH', 'VSCMD_ARG_HOST_ARCH') {
        [System.Environment]::SetEnvironmentVariable($v, $null, 'Process')
    }
    $vcvars = Join-Path $env:VCINSTALLDIR 'Auxiliary\Build\vcvarsall.bat'
    cmd /c "`"$vcvars`" $Arch >nul 2>&1 && set" 2>&1 | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') {
            [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
        }
    }
}

function Invoke-Cl {
    param(
        [string[]]$ClFlags,
        [string]$Source,
        [string]$OutputName,
        [string[]]$LinkLibs,
        [string]$LinkRes,
        [string]$EntryPoint,
        [switch]$NoDefaultLib
    )
    $clArgs = $ClFlags + @($Source, "/Fe:$OutputName", '/link') + $LinkLibs
    if ($LinkRes) { $clArgs += $LinkRes }
    $clArgs += @("/entry:$EntryPoint", '/subsystem:WINDOWS')
    if ($NoDefaultLib) { $clArgs += '/NODEFAULTLIB' }
    & cl @clArgs
    if ($LASTEXITCODE -ne 0) { Write-Error "cl failed for $OutputName" }
}

function Set-PEVersion {
    param(
        [string]$Path,
        [int]$Major,
        [int]$Minor
    )
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    if ([System.Text.Encoding]::ASCII.GetString($bytes, $peOffset, 4) -ne "PE`0`0") {
        Write-Error "$Path is not a valid PE file"
        return
    }
    # PE optional header starts at peOffset + 24. Field offsets from its start:
    #   +40: MajorOperatingSystemVersion (uint16)
    #   +42: MinorOperatingSystemVersion (uint16)
    #   +48: MajorSubsystemVersion      (uint16)
    #   +50: MinorSubsystemVersion      (uint16)
    # These offsets are identical for PE32 and PE32+.
    $opt = $peOffset + 24
    $verBytes = [BitConverter]::GetBytes([uint16]$Major)
    $minBytes = [BitConverter]::GetBytes([uint16]$Minor)
    $bytes[$opt + 40] = $verBytes[0]; $bytes[$opt + 41] = $verBytes[1]
    $bytes[$opt + 42] = $minBytes[0]; $bytes[$opt + 43] = $minBytes[1]
    $bytes[$opt + 48] = $verBytes[0]; $bytes[$opt + 49] = $verBytes[1]
    $bytes[$opt + 50] = $minBytes[0]; $bytes[$opt + 51] = $minBytes[1]
    [System.IO.File]::WriteAllBytes($Path, $bytes)
    Write-Host "  Patched OS and subsystem version to ${Major}.${Minor}"
}

function Build-Template {
    param([string]$Arch, [string]$Name)
    $def = $BuildDefs[$Name]

    Push-Location (Join-Path $ScriptDir $def.Dir)
    try {
        if ($def.RcArgs) {
            & rc @($def.RcArgs)
            if ($LASTEXITCODE -ne 0) { throw "rc failed for $Name ($Arch)" }
        }

        $outName = $def.OutputFmt -f $Arch
        Invoke-Cl -ClFlags $def.ClFlags -Source $def.Source -OutputName $outName `
                  -LinkLibs $def.LinkLibs -LinkRes $def.LinkRes `
                  -EntryPoint $def.EntryPoint -NoDefaultLib:([bool]$def.NoDefaultLib)

        if ($Name -like 'dll*') {
            $outName256 = $outName -replace '(\.\w+)$', '.256kib$1'
            Invoke-Cl -ClFlags ($def.ClFlags + '/DSCSIZE=262144') -Source $def.Source -OutputName $outName256 `
                      -LinkLibs $def.LinkLibs -LinkRes $def.LinkRes `
                      -EntryPoint $def.EntryPoint -NoDefaultLib:([bool]$def.NoDefaultLib)
        }
    } finally { Pop-Location }

    if ($def.PatchVersion) {
        $outPath = Join-Path $ScriptDir "$($def.Dir)\$outName"
        if ($Arch -eq 'x86') {
            Set-PEVersion -Path $outPath -Major 4 -Minor 0
        } else {
            Set-PEVersion -Path $outPath -Major 5 -Minor 2
        }
    }
}

# Build each requested template for each architecture
foreach ($arch in $Architectures) {
    Write-Host "`n=== Configuring for $arch ===" -ForegroundColor Cyan
    Invoke-VCVars $arch

    foreach ($tmpl in $Templates) {
        Write-Host "`nBuilding: $tmpl ($arch)" -ForegroundColor Green
        Build-Template -Arch $arch -Name $tmpl
    }
}

# Clean intermediate files and move outputs
Write-Host "`n=== Cleaning up ===" -ForegroundColor Cyan
Get-ChildItem $ScriptDir -Recurse -File |
    Where-Object { $_.Extension -in '.obj', '.res', '.exp', '.lib' } |
    Remove-Item -Force

Write-Host "`n=== Moving outputs to $OutputDir ===" -ForegroundColor Cyan
Get-ChildItem $ScriptDir -Recurse -File |
    Where-Object { $_.Extension -in '.exe', '.dll' } |
    ForEach-Object {
    Move-Item $_.FullName (Join-Path $OutputDir $_.Name) -Force
    Write-Host "  $($_.Name)"
}

Write-Host "`nDone." -ForegroundColor Green
