On Error Resume Next

Function WindowsZip(sFile, sZipFile)
  'This script is provided under the Creative Commons license located
  'at http://creativecommons.org/licenses/by-nc/2.5/ . It may not
  'be used for commercial purposes with out the expressed written consent
  'of NateRice.com

  Set oZipShell = CreateObject("WScript.Shell")  
  Set oZipFSO = CreateObject("Scripting.FileSystemObject")
  
  If Not oZipFSO.FileExists(sZipFile) Then
    NewZip(sZipFile)
  End If

  Set oZipApp = CreateObject("Shell.Application")
  
  sZipFileCount = oZipApp.NameSpace(sZipFile).items.Count

  aFileName = Split(sFile, "\")
  sFileName = (aFileName(Ubound(aFileName)))
  
  'listfiles
  sDupe = False
  For Each sFileNameInZip In oZipApp.NameSpace(sZipFile).items
    If LCase(sFileName) = LCase(sFileNameInZip) Then
      sDupe = True
      Exit For
    End If
  Next
  
  If Not sDupe Then
    oZipApp.NameSpace(sZipFile).Copyhere sFile

    'Keep script waiting until Compressing is done
    On Error Resume Next
    sLoop = 0
    Do Until sZipFileCount < oZipApp.NameSpace(sZipFile).Items.Count
      Wscript.Sleep(100)
      sLoop = sLoop + 1
    Loop
    On Error GoTo 0
  End If
End Function

Sub NewZip(sNewZip)
  'This script is provided under the Creative Commons license located
  'at http://creativecommons.org/licenses/by-nc/2.5/ . It may not
  'be used for commercial purposes with out the expressed written consent
  'of NateRice.com

  Set oNewZipFSO = CreateObject("Scripting.FileSystemObject")
  Set oNewZipFile = oNewZipFSO.CreateTextFile(sNewZip)
    
  oNewZipFile.Write Chr(80) & Chr(75) & Chr(5) & Chr(6) & String(18, 0)
  
  oNewZipFile.Close
  Set oNewZipFSO = Nothing

  Wscript.Sleep(500)
End Sub

