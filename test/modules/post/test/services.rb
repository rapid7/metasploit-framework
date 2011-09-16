#
# by kernelsmith (kernelsmith+\x40+kernelsmith+\.com)
#

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/services'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::WindowsServices

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'services_post_testing',
				'Description'   => %q{ This module will test windows services methods within a shell},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'kernelsmith'],
				'Version'       => '$Revision: 11663 $',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'shell' ]
			))
		register_options(
			[
				OptBool.new("VERBOSE" , [true, "Verbose test, shows service status after each test", false]),
				OptString.new("QSERVICE" , [true, "Service (keyname) to query", "winmgmt"]),
				OptString.new("NSERVICE" , [true, "New Service (keyname) to create/del", "testes"]),
				OptString.new("SSERVICE" , [true, "Service (keyname) to start/stop", "W32Time"]),
				OptString.new("MODE" , [true, "Mode to use for startup/create tests", "demand"]),
				OptString.new("DNAME" , [true, "Display name used for create test", "Cool display name"]),
				OptString.new("BINPATH" , [true, "Binary path for create test", "C:\\WINDOWS\\system32\\svchost.exe -k netsvcs"]),
			], self.class)

	end

	def run
	
		blab = datastore['VERBOSE']
		print_status("Running against session #{datastore["SESSION"]}")
		print_status("Session type is #{session.type}")
		print_status("Verbosity is set to #{blab.to_s}")
		print_status("Don't be surprised to see some errors as the script is faster")
		print_line("than the windows SCM, just make sure the errors are sane.  You can")
		print_line("set VERBOSE to true to see more details")

		print_status()
		print_status("TESTING service_list")
		results = service_list
		print_status("RESULTS: #{results.class} #{results.pretty_inspect}")
		
		print_status()
		print_status("TESTING service_list_running")
		results = service_list_running
		print_status("RESULTS: #{results.class} #{results.pretty_inspect}")

		print_status()
		print_status("TESTING service_info on servicename: #{datastore["QSERVICE"]}")
		results = service_info(datastore['QSERVICE'])
		print_status("RESULTS: #{results.class} #{results.pretty_inspect}")

		print_status()
		print_status("TESTING service_query_ex on servicename: #{datastore["QSERVICE"]}")
		results = service_query_ex(datastore['QSERVICE'])
		print_status("RESULTS: #{results.class} #{results.pretty_inspect}")

		print_status()
		print_status("TESTING service_query_config on servicename: #{datastore["QSERVICE"]}")
		results = service_query_config(datastore['QSERVICE'])
		print_status("RESULTS: #{results.class} #{results.pretty_inspect}")

		print_status()
		print_status("TESTING service_change_startup on servicename: #{datastore['QSERVICE']} " +
					"to #{datastore['MODE']}")
		results = service_change_startup(datastore['QSERVICE'],datastore['MODE'])
		print_status("RESULTS: #{results.class} #{results.pretty_inspect}")
		print_status("Current status of this service " + 
					"#{service_query_ex(datastore['QSERVICE']).pretty_inspect}") if blab

		print_status()
		print_status("TESTING service_create on servicename: #{datastore['NSERVICE']} using\n" +
					"display_name: #{datastore['DNAME']}, executable_on_host: " + 
					"#{datastore['BINPATH']}, and startupmode: #{datastore['MODE']}")
		results = service_create(datastore['NSERVICE'],datastore['DNAME'],datastore['BINPATH'],datastore['MODE'])
		print_status("RESULTS: #{results.class} #{results.pretty_inspect}")
		print_status("Current status of this service " + 
					"#{service_query_ex(datastore['QSERVICE']).pretty_inspect}") if blab

		print_status()
		print_status("TESTING service_start on servicename: #{datastore['SSERVICE']}")
		results = service_start(datastore['SSERVICE'])
		print_status("RESULTS: #{results.class} #{results.pretty_inspect}")
		print_status("Current status of this service " + 
					"#{service_query_ex(datastore['SSERVICE']).pretty_inspect}") if blab
		print_status("Sleeping to give the service a chance to start")
		select(nil, nil, nil, 2) # give the service time to start, reduces false negatives

		print_status()
		print_status("TESTING service_stop on servicename: #{datastore['SSERVICE']}")
		results = service_stop(datastore['SSERVICE'])
		print_status("RESULTS: #{results.class} #{results.pretty_inspect}")
		print_status("Current status of this service " + 
					"#{service_query_ex(datastore['SSERVICE']).pretty_inspect}") if blab

		print_status()
		print_status("TESTING service_delete on servicename: #{datastore['NSERVICE']}")
		results = service_delete(datastore['NSERVICE'])
		print_status("RESULTS: #{results.class} #{results.pretty_inspect}")
		print_status("Current status of this service " + 
					"#{service_query_ex(datastore['QSERVICE']).pretty_inspect}") if blab
		print_status()
		print_status("Testing complete.")
	end

end
