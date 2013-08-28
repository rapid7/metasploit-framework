##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'rex'
require 'msf/core/post/windows/services'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Services

	def initialize(info={})
		super(update_info(info,
			'Name'                 => "Windows Gather Service Info Enumeration",
			'Description'          => %q{
				This module will query the system for services and display name and configuration
				info for each returned service. It allows you to optionally search the credentials, path, or start
				type for a string and only return the results that match. These query operations
				are cumulative and if no query strings are specified, it just returns all services.
				NOTE: If the script hangs, windows firewall is most likely on and you did not
				migrate to a safe process (explorer.exe for example).
				},
			'License'              => MSF_LICENSE,
			'Platform'             => ['win'],
			'SessionTypes'         => ['meterpreter'],
			'Author'               => ['Keith Faber', 'Kx499']
		))
		register_options(
			[
				OptString.new('CRED', [ false, 'String to search credentials for' ]),
				OptString.new('PATH', [ false, 'String to search path for' ]),
				OptEnum.new('TYPE', [false, 'Service startup Option', 'All', ['All', 'Auto', 'Manual', 'Disabled' ]])
			], self.class)
	end


	def run

		# set vars
		qcred = datastore["CRED"] || nil
		qpath = datastore["PATH"] || nil
		if datastore["TYPE"] == "All"
			qtype = nil
		else
			qtype = datastore["TYPE"]
		end
		if qcred
			print_status("Credential Filter: " + qcred)
		end
		if qpath
			print_status("Executable Path Filter: " + qpath)
		end
		if qtype
			print_status("Start Type Filter: " + qtype)
		end

		print_status("Listing Service Info for matching services:")
		service_list.each do |sname|
			srv_conf = {}
			isgood = true
			#make sure we got a service name
			if sname
				begin
					srv_conf = service_info(sname)
					#filter service based on filters passed, the are cumulative
					if qcred and ! srv_conf['Credentials'].downcase.include? qcred.downcase
						isgood = false
					end
					if qpath and ! srv_conf['Command'].downcase.include? qpath.downcase
						isgood = false
					end
					# There may not be a 'Startup', need to check nil
					if qtype and ! (srv_conf['Startup'] || '').downcase.include? qtype.downcase
						isgood = false
					end

					#if we are still good return the info
					if isgood
						vprint_status("\tName: #{sname}")
						vprint_good("\t\tStartup: #{srv_conf['Startup']}")
						vprint_good("\t\tCommand: #{srv_conf['Command']}")
						vprint_good("\t\tCredentials: #{srv_conf['Credentials']}")
					end
				rescue
					print_error("An error occured enumerating service: #{sname}")
				end
			else
				print_error("Problem enumerating services")
			end

		end
	end

end
