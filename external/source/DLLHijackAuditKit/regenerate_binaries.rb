#!/usr/bin/env ruby

dllbase = File.expand_path(File.dirname(__FILE__))
msfbase = File.expand_path(File.join(dllbase, "..", "..", ".."))
msfp    = File.join(msfbase, "msfpayload")

Dir.chdir(dllbase)

system("ruby #{msfp} windows/exec CMD=calc.exe X > runcalc.exe")
system("ruby #{msfp} windows/exec CMD=calc.exe D > runcalc.dll")
system("ruby #{msfp} windows/exec CMD='cmd.exe /c echo yes > exploited.txt' D > runtest.dll")
system("ruby #{msfp} windows/exec CMD='cmd.exe /c echo yes > exploited.txt' X > runtest.exe")

