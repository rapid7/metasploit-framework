#!/usr/bin/env ruby

File.umask(0022)

# Extract the user's Metasploit source tree
msf3 = '/msf3'
if(! (File.directory?(msf3) and File.exists?(File.join(msf3,"_EXTRACTED_"))))
	puts "[*] The Metasploit Framework is being installed in:"
	puts "[*] - #{msf3}"
	puts "[*] This may take a couple minutes..."
	Dir.chdir('/')
	r = system("tar xf /data/msf3.tar.gz")
	if(not r)
		puts "[-] Extraction failed"
		exec("/bin/bash")
	end
	system("touch #{msf3}/_EXTRACTED_")
end
Dir.chdir(msf3)
puts "[*] Updating the Metasploit Framework..."
puts ""

system("svn update")
puts ""
puts "[*] Update complete"
$stdin.getc
