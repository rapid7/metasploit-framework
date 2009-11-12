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
	File.open("can_write.txt", "wb") do |fd|
		fd.write("YES")
	end
	File.unlink("can_write.txt")
	allowed = true
rescue ::Exception
end

if(not allowed)
	puts "[*] Error: msfupdate must be run as an administrative user"
	$stdin.readline
	exit(1)
end

puts "[*] Updating the Metasploit Framework..."
puts ""

system("svn update")

puts ""
puts "[*] Update complete, press enter to exit"

$stdin.readline
exit(0)

