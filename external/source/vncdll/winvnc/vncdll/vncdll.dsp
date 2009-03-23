# Microsoft Developer Studio Project File - Name="vncdll" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=vncdll - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "vncdll.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "vncdll.mak" CFG="vncdll - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "vncdll - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "vncdll - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "vncdll - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\Release"
# PROP Intermediate_Dir "..\Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VNCDLL_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /Zi /O1 /I "..\omnithread" /I ".." /I "..\.." /D "WIN32" /D "NDEBUG" /D "__x86__" /D "__WIN32__" /D "_WINDOWS" /D "_MBCS" /D "_OMNITHREAD_DLL" /D _WIN32_WINNT=0x400 /FR /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 ws2_32.lib advapi32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386

!ELSEIF  "$(CFG)" == "vncdll - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\Debug"
# PROP Intermediate_Dir "..\Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VNCDLL_EXPORTS" /YX /FD /GZ  /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VNCDLL_EXPORTS" /YX /FD /GZ  /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 ws2_32.lib advapi32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "vncdll - Win32 Release"
# Name "vncdll - Win32 Debug"
# Begin Group "omnithread"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\omnithread\omnithread\nt.cpp
# End Source File
# Begin Source File

SOURCE=..\omnithread\omnithread\nt.h
# End Source File
# Begin Source File

SOURCE=..\omnithread\omnithread.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\winvnc\res\animatedmemoryimagesource.class
# End Source File
# Begin Source File

SOURCE=..\winvnc\res\authenticationpanel.class
# End Source File
# Begin Source File

SOURCE=..\winvnc\res\clipboardframe.class
# End Source File
# Begin Source File

SOURCE=..\winvnc\res\descipher.class
# End Source File
# Begin Source File

SOURCE=..\winvnc\res\icon1.ico
# End Source File
# Begin Source File

SOURCE=..\winvnc\res\optionsframe.class
# End Source File
# Begin Source File

SOURCE=..\winvnc\res\rfbproto.class
# End Source File
# Begin Source File

SOURCE=..\winvnc\res\vnc.bmp
# End Source File
# Begin Source File

SOURCE=..\winvnc\res\vnccanvas.class
# End Source File
# Begin Source File

SOURCE=..\winvnc\res\vncviewer.class
# End Source File
# Begin Source File

SOURCE=..\winvnc\res\vncviewer.jar
# End Source File
# Begin Source File

SOURCE=..\winvnc\res\winvnc.ico
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\winvnc\d3des.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\keysymdef.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\resource.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\rfb.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\rfbMisc.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\rfbRect.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\rfbRegion.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\rfbRegion_win32.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\rfbRegion_X11.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\rfbUpdateTracker.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\stdhdrs.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\translate.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vnc.hh
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncabout.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncacceptdialog.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncauth.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncbuffer.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncclient.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncconndialog.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vnccorbaconnect.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncdesktop.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncencodecorre.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncencodehext.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncencodemgr.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncencoder.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncencoderre.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncencodezrle.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vnchttpconnect.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncinsthandler.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vnckeymap.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vnclog.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncmenu.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncpasswd.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncproperties.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncserver.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncservice.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncsockconnect.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vnctimedmsgbox.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vsocket.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\vtypes.h
# End Source File
# Begin Source File

SOURCE=..\winvnc\winvnc.h
# End Source File
# End Group
# Begin Group "Source Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\winvnc\buildtime.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\d3des.c
# End Source File
# Begin Source File

SOURCE=..\winvnc\rfbRegion.cpp

!IF  "$(CFG)" == "vncdll - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "vncdll - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\winvnc\rfbRegion_win32.cpp

!IF  "$(CFG)" == "vncdll - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "vncdll - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\winvnc\rfbRegion_X11.cxx

!IF  "$(CFG)" == "vncdll - Win32 Release"

!ELSEIF  "$(CFG)" == "vncdll - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\winvnc\rfbUpdateTracker.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\stdhdrs.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\tableinitcmtemplate.cpp

!IF  "$(CFG)" == "vncdll - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "vncdll - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\winvnc\tableinittctemplate.cpp

!IF  "$(CFG)" == "vncdll - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "vncdll - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\winvnc\tabletranstemplate.cpp

!IF  "$(CFG)" == "vncdll - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "vncdll - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\winvnc\translate.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncabout.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncacceptdialog.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncauth.c
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncbuffer.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncclient.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncconndialog.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vnccorbaconnect.cpp

!IF  "$(CFG)" == "vncdll - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "vncdll - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\winvnc\vncdesktop.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncencodecorre.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncencodehext.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncencoder.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncencoderre.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncencodezrle.cxx
# End Source File
# Begin Source File

SOURCE=..\winvnc\vnchttpconnect.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncinsthandler.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vnckeymap.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vnclog.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncmenu.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncproperties.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncserver.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncservice.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vncsk.cpp

!IF  "$(CFG)" == "vncdll - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "vncdll - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\winvnc\vncsockconnect.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vnctimedmsgbox.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\vsocket.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\winvnc.cpp
# End Source File
# Begin Source File

SOURCE=..\winvnc\winvnc.def
# End Source File
# Begin Source File

SOURCE=..\winvnc\winvnc.rc
# End Source File
# End Group
# Begin Source File

SOURCE=..\..\BUILDING.txt
# End Source File
# Begin Source File

SOURCE=..\building.txt
# End Source File
# Begin Source File

SOURCE=..\history.txt
# End Source File
# Begin Source File

SOURCE=..\..\LICENCE.txt
# End Source File
# Begin Source File

SOURCE=..\README_BINARY.txt
# End Source File
# End Target
# End Project
