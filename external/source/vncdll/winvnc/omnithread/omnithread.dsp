# Microsoft Developer Studio Project File - Name="omnithread" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=omnithread - Win32 Profile
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "omnithread.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "omnithread.mak" CFG="omnithread - Win32 Profile"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "omnithread - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "omnithread - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "omnithread - Win32 Release CORBA" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "omnithread - Win32 Release CORBA DEBUG" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "omnithread - Win32 Profile" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "omnithread - Win32 Release"

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
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OMNITHREAD_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "." /D "NDEBUG" /D "__WIN32__" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OMNITHREAD_EXPORTS" /D "_OMNITHREAD_DLL" /D _WIN32_WINNT=0x400 /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 /nologo /dll /machine:I386 /out:"..\Release/othread2.dll"

!ELSEIF  "$(CFG)" == "omnithread - Win32 Debug"

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
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OMNITHREAD_EXPORTS" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "." /D "_DEBUG" /D "__WIN32__" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OMNITHREAD_EXPORTS" /D "_OMNITHREAD_DLL" /D _WIN32_WINNT=0x400 /YX /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 /nologo /dll /debug /machine:I386 /out:"..\Debug/othread2d.dll" /pdbtype:sept

!ELSEIF  "$(CFG)" == "omnithread - Win32 Release CORBA"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "omnithread___Win32_Release_CORBA"
# PROP BASE Intermediate_Dir "omnithread___Win32_Release_CORBA"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\Release_CORBA"
# PROP Intermediate_Dir "..\Release_CORBA"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /I "." /D "NDEBUG" /D "__WIN32__" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OMNITHREAD_EXPORTS" /D "_OMNITHREAD_DLL" /D _WIN32_WINNT=0x400 /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "." /D "NDEBUG" /D "__WIN32__" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OMNITHREAD_EXPORTS" /D "_OMNITHREAD_DLL" /D _WIN32_WINNT=0x400 /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 /nologo /dll /machine:I386 /out:"..\Release_CORBA/othread2.dll"

!ELSEIF  "$(CFG)" == "omnithread - Win32 Release CORBA DEBUG"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "omnithread___Win32_Release_CORBA_DEBUG"
# PROP BASE Intermediate_Dir "omnithread___Win32_Release_CORBA_DEBUG"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\Release_CORBA_DEBUG"
# PROP Intermediate_Dir "..\Release_CORBA_DEBUG"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "." /D "NDEBUG" /D "__WIN32__" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OMNITHREAD_EXPORTS" /D "_OMNITHREAD_DLL" /D _WIN32_WINNT=0x400 /YX /FD /c
# ADD CPP /nologo /MDd /W3 /GX /ZI /Od /I "." /D "_DEBUG" /D "__WIN32__" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OMNITHREAD_EXPORTS" /D "_OMNITHREAD_DLL" /D _WIN32_WINNT=0x400 /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /nologo /dll /machine:I386 /out:"..\Release_CORBA/omnithread2_rt.dll"
# ADD LINK32 /nologo /dll /incremental:yes /debug /machine:I386 /out:"..\Release_CORBA_DEBUG/othread2d.dll"

!ELSEIF  "$(CFG)" == "omnithread - Win32 Profile"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "omnithread___Win32_Profile"
# PROP BASE Intermediate_Dir "omnithread___Win32_Profile"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\Profile"
# PROP Intermediate_Dir "..\Profile"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "." /D "_DEBUG" /D "__WIN32__" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OMNITHREAD_EXPORTS" /D "_OMNITHREAD_DLL" /D _WIN32_WINNT=0x400 /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "." /D "_DEBUG" /D "__WIN32__" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OMNITHREAD_EXPORTS" /D "_OMNITHREAD_DLL" /D _WIN32_WINNT=0x400 /YX /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /nologo /dll /debug /machine:I386 /out:"..\Debug/omnithread2_rtd.dll" /pdbtype:sept
# ADD LINK32 /nologo /dll /profile /debug /machine:I386 /out:"..\Profile/othread2d.dll"

!ENDIF 

# Begin Target

# Name "omnithread - Win32 Release"
# Name "omnithread - Win32 Debug"
# Name "omnithread - Win32 Release CORBA"
# Name "omnithread - Win32 Release CORBA DEBUG"
# Name "omnithread - Win32 Profile"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\omnithread\nt.cpp
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\omnithread\nt.h
# End Source File
# Begin Source File

SOURCE=.\omnithread.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
