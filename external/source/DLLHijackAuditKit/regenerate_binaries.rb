#!/usr/bin/env ruby

dllbase = File.expand_path(File.dirname(__FILE__))
msfbase = File.expand_path(File.join(dllbase, "..", "..", ".."))
msfv    = File.join(msfbase, "msfvenom")

Dir.chdir(dllbase)

system("ruby #{msfv} -p windows/exec CMD=calc.exe -f exe -o runcalc.exe")
system("ruby #{msfv} -p windows/exec CMD=calc.exe -f dll -o runcalc.dll")
system("ruby #{msfv} -p windows/exec CMD='cmd.exe /c echo yes > exploited.txt' -f dll -o runtest.dll")
system("ruby #{msfv} -p windows/exec CMD='cmd.exe /c echo yes > exploited.txt' -f exe -o runtest.exe")

