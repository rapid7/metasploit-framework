
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
				'Name'          => 'test',
				'Description'   => %q{ This module will test registry stuff },
				'License'       => MSF_LICENSE,
				'Author'        => [ 'kernelsmith'],
				'Version'       => '$Revision$',
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

		print_status "testing get_val_info for key:#{datastore['KEY']}, val:#{datastore['VALUE']}"
		results = registry_getvalinfo(datastore['KEY'], datastore['VALUE'])
		print_status("results: #{results.class} #{results.inspect}")
		print_status "testing get_val_data for key:#{datastore['KEY']}, val:#{datastore['VALUE']}"
		results = registry_getvaldata(datastore['KEY'], datastore['VALUE'])
		print_status("results: #{results.class} #{results.inspect}")

		print_status "testing create_key for key:#{datastore['KEY']}\\test"
		results = registry_createkey("#{datastore['KEY']}\\test")
		print_status("results: #{results.class} #{results.inspect}")

		print_status "testing set_val_data for key:#{datastore['KEY']}\\test, val:test, data:test, type:REG_SZ"
		results = registry_setvaldata("#{datastore['KEY']}\\test", "test", "test", "REG_SZ")
		print_status("results: #{results.class} #{results.inspect}")

		print_status "getting newly created val_info for key:#{datastore['KEY']}\\test, val:test"
		results = registry_getvalinfo("#{datastore['KEY']}\\test", "test")
		print_status("results: #{results.class} #{results.inspect}")

		print_status "testing del_val_data for key:#{datastore['KEY']}\\test, val:test"
		results = registry_deleteval("#{datastore['KEY']}\\test", "test")
		print_errror("registry_deleteval reported failure") unless results
		print_status("results: #{results.class} #{results.inspect}")

		print_status "testing del_key"
		results = registry_deletekey("#{datastore['KEY']}\\test")
		print_status("results: #{results.class} #{results.inspect}")

		print_status "getting deleted val_info for key:#{datastore['KEY']}\\test, val:test, this should return nils"
		results = registry_getvalinfo("#{datastore['KEY']}\\test", "test")
		if (results.nil?)
			print_status("Delete worked correctly")
		else
			print_error("Deleted key is still there!")
		end

		print_status "testing enum_keys"
		results = registry_enumkeys(datastore['KEY'])
		print_status("results: #{results.class} #{results.inspect}")

		print_status "testing enum_vals"
		results = registry_enumvals(datastore['KEY'])
		print_status("results: #{results.class} #{results.inspect}")

	end

end


