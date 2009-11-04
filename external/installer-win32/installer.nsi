; HM NIS Edit Wizard helper defines
!define PRODUCT_NAME "Metasploit Framework"
!define PRODUCT_VERSION "3.3"
!define PRODUCT_PUBLISHER "Rapid7 LLC"
!define PRODUCT_WEB_SITE "http://metasploit.com/framework/"

VIProductVersion "3.3.0.3"
VIAddVersionKey /LANG=1033 "ProductName" "Metasploit Framework"
VIAddVersionKey /LANG=1033 "Comments" "This is the official installer for Metasploit 3"
VIAddVersionKey /LANG=1033 "CompanyName" "Rapid7 LLC"
VIAddVersionKey /LANG=1033 "LegalTrademarks" "Metasploit is a registered trademark of Rapid7 LLC"
VIAddVersionKey /LANG=1033 "LegalCopyright" " Copyright (C) 2003-2009 Rapid7 LLC"
VIAddVersionKey /LANG=1033 "FileDescription" "Metasploit 3 Windows Installer"
VIAddVersionKey /LANG=1033 "FileVersion" "3.3.0.3"

SetCompressor /SOLID lzma

; MUI 1.67 compatible ------
!include "MUI.nsh"

; MUI Settings
!define MUI_ABORTWARNING


; Welcome page
!insertmacro MUI_PAGE_WELCOME

; License page
!insertmacro MUI_PAGE_LICENSE "metasploit_license.txt"

; Directory page
!insertmacro MUI_PAGE_DIRECTORY

; Instfiles page
!insertmacro MUI_PAGE_INSTFILES

; Finish page
; !insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_INSTFILES

; Language files
!insertmacro MUI_LANGUAGE "English"

; Reserve files
!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS

; MUI end ------

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "output.exe"
InstallDir "C:\msf3"
ShowInstDetails show
ShowUnInstDetails show

Section "MainSection" SecCore
       SetOutPath $INSTDIR
       File /r "/home/hdm/cygwin/msf3/\*.*"
SectionEnd

Section -AdditionalIcons
  SetShellVarContext all
SectionEnd

Section -Post
  WriteUninstaller "$INSTDIR\uninst.exe"
SectionEnd

Function un.onUninstSuccess
  ;HideWindow
  MessageBox MB_ICONINFORMATION|MB_OK "$(^Name) was successfully removed from your computer."
FunctionEnd

Function un.onInit
  MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "Are you sure you want to completely remove $(^Name) and all of its components?" IDYES +2
  Abort
FunctionEnd

Section Uninstall
  RMDir /r "$INSTDIR"
  SetAutoClose true
SectionEnd

