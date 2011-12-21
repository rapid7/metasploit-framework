
##
# $Id: registry.rb 13739 2011-09-16 20:32:22Z egypt $
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

	include Msf::Post::Windows::Registry

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'registry_post_testing',
				'Description'   => %q{ This module will test registry code used in post modules},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'kernelsmith'],
				'Version'       => '$Revision: 13739 $',
				'Platform'      => [ 'windows' ]
			))
		register_options(
		[
				OptString.new("KEY" , [true, "Registry key to test", "HKLM\\Software\\Microsoft\\Active Setup"]),
				OptString.new("VALUE" , [true, "Registry value to test", "DisableRepair"]),
			], self.class)

	end

	def run
		print_status("Running against session #{datastore["SESSION"]}")
		print_status("Session type is #{session.type}")

		print_status()
		print_status("TESTING:  registry_value_exist? for key:#{datastore['KEY']}, val:#{datastore['VALUE']}")
		results = registry_value_exist?(datastore['KEY'],datastore['VALUE'])
		print_status("RESULTS:  #{results.class} #{results.inspect}")
		
		print_status()
		print_status("TESTING:  registry_value_exist? for key:#{'HKLM\\Non\Existent\key'}, val:#{datastore['VALUE']}")
		results = registry_value_exist?('HKLM\\Non\Existent\key',datastore['VALUE'])
		print_status("RESULTS (Expecting false):  #{results.class} #{results.inspect}")
		
		print_status()
		print_status("TESTING:  registry_value_exist? for key:#{datastore['KEY']}, val:'NonExistentValue'")
		results = registry_value_exist?(datastore['KEY'],'NonExistentValue')
		print_status("RESULTS (Expecting false):  #{results.class} #{results.inspect}")
		
		print_status()
		print_status("TESTING:  registry_key_exist? for key: 'HKLM\\Non\Existent\key'")
		results = registry_key_exist?('HKLM\\Non\Existent\key')  # need to error handle this properly in meterp ver
		print_status("RESULTS (Expecting false):  #{results.class} #{results.inspect}")
		
		print_status()
		print_status("TESTING:  registry_key_exist? for key:#{datastore['KEY']}")
		results = registry_key_exist?(datastore['KEY'])
		print_status("RESULTS:  #{results.class} #{results.inspect}")
		
		print_status()
		print_status("TESTING:  registry_getvalinfo for key:#{datastore['KEY']}, val:#{datastore['VALUE']}")
		results = registry_getvalinfo(datastore['KEY'], datastore['VALUE'])
		print_error("reported failure") unless results
		print_status("RESULTS:  #{results.class} #{results.inspect}")
		
		print_status()
		print_status("TESTING:  registry_getvaldata for key:#{datastore['KEY']}, val:#{datastore['VALUE']}")
		results = registry_getvaldata(datastore['KEY'], datastore['VALUE'])
		print_error("reported failure") unless results
		print_status("RESULTS:  #{results.class} #{results.inspect}")

		print_status()
		print_status("TESTING:  registry_createkey for key:#{datastore['KEY']}\\test")
		results = registry_createkey("#{datastore['KEY']}\\test")
		print_error("reported failure") if results
		print_status("RESULTS:  #{results.class} #{results.inspect}")

		print_status()
		print_status("TESTING:  registry_setvaldata for key:#{datastore['KEY']}\\test, val:test, data:test, type:REG_SZ")
		results = registry_setvaldata("#{datastore['KEY']}\\test", "test", "test", "REG_SZ")
		print_error("reported failure") if results
		print_status("RESULTS:  #{results.class} #{results.inspect}")

		print_status()
		print_status("Running registry_getvalinfo for freshly created key:#{datastore['KEY']}\\test, val:test")
		results = registry_getvalinfo("#{datastore['KEY']}\\test", "test")
		print_error("reported failure") unless results
		print_status("RESULTS:  #{results.class} #{results.inspect}")

		print_status()
		print_status("TESTING:  registry_deleteval for key:#{datastore['KEY']}\\test, val:test")
		results = registry_deleteval("#{datastore['KEY']}\\test", "test")
		print_error("reported failure") if results
		print_status("RESULTS:  #{results.class} #{results.inspect}")

		print_status()
		print_status("TESTING:  registry_deletekey")
		results = registry_deletekey("#{datastore['KEY']}\\test")
		print_error("reported failure") if results
		print_status("RESULTS:  #{results.class} #{results.inspect}")

		print_status()
		print_status("Running registry_getvalinfo for deleted key:#{datastore['KEY']}\\test, val:test")
		print_status("NOTE: this OUGHT to throw an error which this test will catch")
		errored_out = false
		error_type = Rex::Post::Meterpreter::RequestError
		
		begin
			results = registry_getvalinfo("#{datastore['KEY']}\\test", "test")
		rescue error_type => e
			errored_out = true
		end
		
		print_status("RESULTS (Expecting to catch #{error_type.to_s}):")
		if errored_out
			print_good("Good, the error was:  #{e.class} #{e.to_s}")
		else print_error("Failed, did not catch an #{error_type.to_s}")
		end
		
		print_status()
		print_status("TESTING:  registry_enumkeys")
		results = registry_enumkeys(datastore['KEY'])
		print_error("reported failure") unless results
		print_status("RESULTS:  #{results.class} #{results.inspect}")

		print_status()
		print_status("TESTING:  registry_enumvals")
		results = registry_enumvals(datastore['KEY'])
		print_error("reported failure") unless results
		print_status("RESULTS:  #{results.class} #{results.inspect}")
		
		print_status()
		print_status("Testing Complete!")

	end

end


