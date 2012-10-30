##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Priv
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize(info={})
		super(
			'Name'         => 'Windows Local Admin Search',
			'Description'  => %q{
				This module will identify systems in a given range that the
				supplied domain user (should migrate into a user pid) has administrative
				access to by using the windows api OpenSCManagerA to establishing a handle
				to the remote host. If local admin is found it will then enumerate logged in
				users using NetSessionEnum api.
				},
			'License'      => MSF_LICENSE,
			'Version'      => '$Revision: 14767 $',
			'Author'       => [ 'Brandon McCann "zeknox" <bmccann [at] accuvant.com>',
						'Thomas McCarthy "smilingracoon" <smilingracoon [at] gmail.com>'],
			'Platform'     => [ 'windows'],
			'SessionTypes' => [ 'meterpreter' ]
		)
	end

	def run()
		if is_system?
			# running as SYSTEM and will not pass any network credentials
			print_error "Running as SYSTEM, module should be run with USER level rights"
			return
		else
			super
		end
	end

	# main contrl method
	def run_host(ip)
		connect(ip)
	end

	# enumerate logged in users
	def enum_users(host)
		rail = client.railgun.netapi32
		enumerator = rail.NetSessionEnum("\\\\#{host}", nil, nil,502, 0, "MAX_PREFERRED_LENGTH", 0, 0, 0)
		print_status(enumerator["return"])
	end

	# method to connect to remote host using windows api
	def connect(host)
		user = client.sys.config.getuid
		# use railgun and OpenSCManagerA api to connect to remote host
		adv = client.railgun.advapi32
		manag = adv.OpenSCManagerA("\\\\#{host}", nil, 0xF003F) # SC_MANAGER_ALL_ACCESS

		if(manag["return"] != 0) # we have admin rights
			print_good("#{host.ljust(16)} #{user} - Local admin found")
			# close the handle if connection was made
			adv.CloseServiceHandle(manag["return"])

			enum_users(host)

			# append data to loot table within database
			db_note(host, user)
		else
			# we dont have admin rights
			print_error("#{host.ljust(16)} #{user} - No Local Admin rights")
		end
	end

	def db_note(host, user)
		# write the local admin privs to the database
		if db
			store_loot(
				"#{user}.localadmin",
				'text/plain',
				session,
				"#{host}:#{user}",
				'hosts_localadmin.txt',
				'Local Admin on Hosts'
			)
		end
	end
end