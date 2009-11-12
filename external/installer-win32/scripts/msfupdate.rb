#!/usr/bin/env ruby

File.umask(0022)

msf3 = '/msf3'
if ! File.directory?(msf3)
	puts "[*] This Metasploit Framework installation is corrupted."
	exit(1)
end

Dir.chdir(msf3)

begin
	fd = File.open("/bin/bash", "a")
	fd.close
rescue ::Exception
	puts "[*] Error: msfupdate must be run as an administrative user"
	sleep(30)
	exit(1)
end

puts "[*] Updating the Metasploit Framework..."
puts ""

system("svn update")

puts ""
puts "[*] Update complete"

sleep(10)
exit(0)

