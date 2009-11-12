@echo off

set BASE=%~dp0
cd %BASE%

set TARG=msfrun.rb msfconsole -L
shell.bat
