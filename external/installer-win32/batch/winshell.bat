@echo off

set BASE=%~dp0
cd %BASE%

set PATH="%BASE%bin";"%BASE%usr\X11R6\bin";"%BASE%tools";%PATH%

bin\umount -c >nul 2>&1
bin\umount -A
bin\mount -bfu "%BASE%/" /
bin\mount -bfu "%BASE%/bin" /usr/bin
bin\mount -bfu "%BASE%/lib" /usr/lib

if not defined TARG set TARG=/bin/bash
bin\bash --login -c "%TARG%"