@echo off

set BASE=%~dp0
cd %BASE%

set PATH="%BASE%bin";"%BASE%usr\X11R6\bin";"%BASE%tools";%PATH%


if not defined TARG set TARG=/bin/bash

start bin\rxvt.exe -display :0 -geometry 110x38 -sr -sl 5000 -fn "Lucida Console-12" -bg black -fg white -tn rxvt-cygwin-native -e /bin/bash --login -c "%TARG%"