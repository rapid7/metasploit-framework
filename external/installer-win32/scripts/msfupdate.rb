#!/usr/bin/env ruby

File.umask(0022)

msf3 = '/msf3'
if ! File.directory?(msf3)
	puts "[*] This Metasploit Framework installation is corrupted."
	exit(1)
end

Dir.chdir(msf3)

allowed = false
begin
	File.open(".svn/write_test.txt", "wb") do |fd|
		fd.write("YES")
	end
	File.unlink(".svn/write_test.exe")
	allowed = true
rescue ::Exception
end

if(not allowed)
	puts "[*] Error: msfupdate must be run as an administrative user"
	sleep(30)
	exit(1)
end

puts "[*] Updating the Metasploit Framework..."
puts ""

system("svn update")

puts ""
puts "[*] Update complete, press enter to exit"

sleep(10)
exit(0)

