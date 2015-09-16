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

if not "!arg:~-1,1!" == "\" (
	@set arg=!arg!\
)


for /f %%f in ('dir /B %arg%') DO (
	@set fname=%%f
	@set lastfourchars=!fname:~-4,4!
	if "!lastfourchars!" == ".msu" (
		@set newname=!fname:~0,-4!
		mkdir %arg%!newname!
		mkdir %arg%!newname!\extracted
		expand /F:* %arg%!fname! %arg%!newname!
		expand /F:* %arg%!newname!\!newname!.cab %arg%!newname!\extracted
	)

)

echo Done!
echo Now go to %arg%,
echo and then use the search feature from Windows to
echo find the files you're interested in.