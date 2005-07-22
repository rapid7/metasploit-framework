# Microsoft Developer Studio Project File - Name="ext_server_stdapi" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=ext_server_stdapi - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "ext_server_stdapi.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ext_server_stdapi.mak" CFG="ext_server_stdapi - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ext_server_stdapi - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "ext_server_stdapi - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "ext_server_stdapi - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "EXT_SERVER_SYS_EXPORTS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /Zi /O2 /I "..\..\source\extensions\stdapi\server" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "EXT_SERVER_SYS_EXPORTS" /Yu"precomp.h" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 iphlpapi.lib shlwapi.lib ws2_32.lib metsrv.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /pdb:none /map /machine:I386 /libpath:"..\metsrv\Release"
# SUBTRACT LINK32 /debug
# Begin Special Build Tool
SOURCE="$(InputPath)"
PostBuild_Cmds=copy release\ext_server_stdapi.dll ..\..\output\extensions
# End Special Build Tool

!ELSEIF  "$(CFG)" == "ext_server_stdapi - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "EXT_SERVER_SYS_EXPORTS" /YX /FD /GZ /c
# ADD CPP /nologo /ML /W3 /Gm /GX /ZI /Od /I "..\..\source\extensions\stdapi\server" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "EXT_SERVER_SYS_EXPORTS" /Yu"precomp.h" /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 iphlpapi.lib shlwapi.lib ws2_32.lib metsrv.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept /libpath:"..\metsrv\Debug"
# Begin Special Build Tool
SOURCE="$(InputPath)"
PostBuild_Cmds=copy debug\ext_server_stdapi.dll ..\..\output\extensions
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "ext_server_stdapi - Win32 Release"
# Name "ext_server_stdapi - Win32 Debug"
# Begin Group "Source"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Group "fs"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\fs\dir.c
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\fs\file.c
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\fs\fs.h
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\fs\fs_util.c
# End Source File
# End Group
# Begin Group "net"

# PROP Default_Filter ""
# Begin Group "config"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\net\config\interface.c
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\net\config\route.c
# End Source File
# End Group
# Begin Group "socket"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\net\socket\tcp.c
# End Source File
# End Group
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\net\net.c
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\net\net.h
# End Source File
# End Group
# Begin Group "sys"

# PROP Default_Filter ""
# Begin Group "process"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\sys\process\image.c
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\sys\process\memory.c
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\sys\process\process.c
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\sys\process\process.h
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\sys\process\thread.c
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\sys\process\util.c
# End Source File
# End Group
# Begin Group "registry"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\sys\registry\registry.c
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\sys\registry\registry.h
# End Source File
# End Group
# Begin Group "power"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\sys\power\power.c
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\sys\power\power.h
# End Source File
# End Group
# Begin Group "eventlog"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\sys\eventlog\eventlog.c
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\sys\eventlog\eventlog.h
# End Source File
# End Group
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\sys\sys.h
# End Source File
# End Group
# Begin Group "ui"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\ui\idle.c
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\ui\keyboard.c
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\ui\mouse.c
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\ui\ui.c
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\ui\ui.h
# End Source File
# End Group
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\general.c
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\precomp.h
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\stdapi.c
# ADD CPP /Yc"precomp.h"
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\stdapi.h
# End Source File
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\resource\stdapi.rc
# End Source File
# End Group
# Begin Source File

SOURCE=..\..\source\extensions\stdapi\server\resource\hook.dll
# End Source File
# End Target
# End Project
