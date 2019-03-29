@ECHO OFF
IF "%VSINSTALLDIR%" == "" GOTO NEED_VS

SET FRAMEWORKDIR=%VSINSTALLDIR%..\Reference Assemblies\Microsoft\Framework\.NETFramework
SET DNETDIR=%WINDIR%\Microsoft.NET\Framework
SET TARGETDIR=..\..\..\data\SqlClrPayload

mkdir "%TARGETDIR%" 2> NUL

SET VER=v2.0
SET FW=%DNETDIR%\v2.0.50727
IF EXIST "%FW%" (
  ECHO Building SqlClrPayload for .NET %VER%
  mkdir "%TARGETDIR%\%VER%" 2> NUL
  csc.exe /nologo /noconfig /unsafe+ /nowarn:1701,1702,2008 /nostdlib+ /errorreport:none /warn:4 /errorendlocation /preferreduilang:en-US /highentropyva- /reference:"%FW%\mscorlib.dll" /reference:"%FW%\System.Data.dll" /reference:"%FW%\System.dll" /debug- /filealign:512 /optimize+ /out:%TARGETDIR%\%VER%\SqlClrPayload.dll /target:library /utf8output StoredProcedures.cs AssemblyInfo.cs AssemblyAttributes-%VER%.cs
)

SET VER=v3.5
SET CORE=%FRAMEWORKDIR%\..\%VER%
SET FW=%DNETDIR%\v2.0.50727
IF EXIST "%CORE%" (
  ECHO Building SqlClrPayload for .NET %VER%
  mkdir "%TARGETDIR%\%VER%" 2> NUL
  csc.exe /nologo /noconfig /unsafe+ /nowarn:1701,1702,2008 /nostdlib+ /errorreport:none /warn:4 /errorendlocation /preferreduilang:en-US /highentropyva- /reference:"%FW%\mscorlib.dll" /reference:"%CORE%\System.Core.dll" /reference:"%FW%\System.Data.dll" /reference:"%FW%\System.dll" /debug- /filealign:512 /optimize+ /out:%TARGETDIR%\%VER%\SqlClrPayload.dll /target:library /utf8output StoredProcedures.cs AssemblyInfo.cs AssemblyAttributes-%VER%.cs
)

FOR %%v IN (v4.0 v4.5 v4.5.1 v4.5.2 v4.6 v4.6.1) DO CALL :BUILDLATEST %%v

ECHO Done.
GOTO :END

:NEED_VS
ECHO "This command must be executed from within a Visual Studio Command prompt."
ECHO "This can be found under Microsoft Visual Studio 2013 -> Visual Studio Tools"

:END

EXIT /B 0

:BUILDLATEST
SET VER=%~1
SET FW=%FRAMEWORKDIR%\%VER%
IF EXIST "%FW%" (
  ECHO Building SqlClrPayload for .NET %VER%
  mkdir "%TARGETDIR%\%VER%" 2> NUL
  csc.exe /nologo /noconfig /unsafe+ /nowarn:1701,1702,2008 /nostdlib+ /errorreport:none /warn:4 /errorendlocation /preferreduilang:en-US /highentropyva- /reference:"%FW%\mscorlib.dll" /reference:"%FW%\System.Core.dll" /reference:"%FW%\System.Data.dll" /reference:"%FW%\System.dll" /debug- /filealign:512 /optimize+ /out:%TARGETDIR%\%VER%\SqlClrPayload.dll /target:library /utf8output StoredProcedures.cs AssemblyInfo.cs AssemblyAttributes-%VER%.cs
)
EXIT /B 0
