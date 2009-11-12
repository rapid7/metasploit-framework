@echo off

set BASE=%~dp0
cd %BASE%

set TARG=msfrun.rb tools/nasm_shell.rb
shell.bat