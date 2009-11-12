@echo off

set BASE=%~dp0
cd %BASE%

set TARG=msfrun.rb tools/msf_irb_shell.rb
shell.bat