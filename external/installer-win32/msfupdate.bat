@echo off

set BASE=%~dp0
cd %BASE%msf3

set PATH="%BASE%bin";"%BASE%bin\svn\bin";"%BASE%bin\ruby\bin";"%BASE%tools";%PATH%

svn up

echo Done
pause