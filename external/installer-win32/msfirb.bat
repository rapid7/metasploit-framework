@echo off

set BASE=%~dp0
cd %BASE%
set PATH="%BASE%bin";"%BASE%bin\svn\bin";"%BASE%bin\ruby\bin";"%BASE%tools";%PATH%

start console.exe -t "Metasploit IRB"

