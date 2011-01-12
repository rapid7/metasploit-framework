##
# $Id$
##

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

	include Msf::Post::Registry

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Enumerate logged on users',
				'Description'   => %q{ This module will enumerate current and recent logged on users},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
		register_options(
			[
				OptBool.new('CURRENT', [ true, 'Enumerate currently logged on users', true]),
				OptBool.new('RECENT' , [ true, 'Enumerate Recently logged on users' , true])
			], self.class)

	end


	def ls_logged
		sids = []
		sids << registry_enumkeys("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
		tbl = Rex::Ui::Text::Table.new(
			'Header'  => "Logged Users",
			'Indent'  => 1,
			'Columns' =>
			[
				"SID",
				"Profile Path"
			])
		sids.flatten.each do |sid|
			profile_path = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\#{sid}","ProfileImagePath")
			tbl << [sid,profile_path]
		end
		print_line("\n" + tbl.to_s + "\n")
	end

	def ls_current
		key_base, username = "",""
		tbl = Rex::Ui::Text::Table.new(
			'Header'  => "Current Logged Users",
			'Indent'  => 1,
			'Columns' =>
			[
				"SID",
				"User"
			])
		registry_enumkeys("HKU").each do |sid|
			case sid
			when "S-1-5-18"
				username = "SYSTEM"
				tbl << [sid,username]
			when "S-1-5-19"
				username = "Local Service"
				tbl << [sid,username]
			when "S-1-5-20"
				username = "Network Service"
				tbl << [sid,username]
			else
				if sid =~ /S-1-5-21-\d*-\d*-\d*-\d*$/
					key_base = "HKU\\#{sid}"
					os = session.sys.config.sysinfo['OS']
					if os =~ /(Windows 7|2008|Vista)/
						username = registry_getvaldata("#{key_base}\\Volatile Environment","USERNAME")
					elsif os =~ /(2000|NET|XP)/
						appdata_var = registry_getvaldata("#{key_base}\\Volatile Environment","APPDATA")
						username = appdata_var.scan(/^\w\:\D*\\(\D*)\\\D*$/)
					end
					tbl << [sid,username]
				end
			end
		end
		print_line("\n" + tbl.to_s + "\n")
	end


	def run
		print_status("Running against session #{datastore['SESSION']}")

		if datastore['CURRENT']
			ls_current
		end

		if datastore['RECENT']
			ls_logged
		end

	end
end
