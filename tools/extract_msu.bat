@echo off
@setlocal EnableDelayedExpansion

@set arg=%~1

if [%arg%] == [] (
	echo Argument Missing:
	echo You must provide a directory that contains
	echo all the Windows patches in *.msu format.
	echo To Download patches manually, please go:
	echo http://mybulletins.technet.microsoft.com/BulletinPages/Dashboard
	exit /B
)


for /f %%f in ('dir /B %arg%') DO (
	@set fname=%%f
	@set lastfourchars=!fname:~-4,4!
	if "!lastfourchars!" == ".msu" (
		@set newname=!fname:~0,-4!
		7za e !fname! -o!newname!
		mkdir !newname!\extracted
		expand /F:* !newname!\!newname!.cab !newname!\extracted
	)
)

echo Done!
echo Now go to %arg%,
echo and then use the search feature from Windows to
echo find the files you're interested in.