#!/usr/bin/env ruby

File.umask(0022)


msf3 = '/msf3'
if ! File.directory?(msf3)
	puts "[*] This Metasploit Framework installation is corrupted."
	exit(1)
end

Dir.chdir(msf3)
targ = ARGV.shift
exec("ruby", targ, *ARGV)

