
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

class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'railgun_testing',
				'Description'   => %q{ This module will test railgun code used in post modules},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'kernelsmith'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows' ]
			))
		register_options(
		[
				OptInt.new("ERR_CODE" , [true, "Error code to reverse lookup", 0x420]),
				OptInt.new("WIN_CONST", [true, "Windows constant to reverse lookup", 4]),
				OptString.new("WCREGEX", [false,"Regexp to apply to constant rev lookup", "^SERVICE"]),
				OptString.new("ECREGEX", [false,"Regexp to apply to error code lookup", "^ERROR_SERVICE_"]),
			], self.class)

	end

	def run
		print_status("Running against session #{datastore["SESSION"]}")
		print_status("Session type is #{session.type}")

		@rg = session.railgun

		print_status()
		print_status("TESTING:  const_reverse_lookup on #{datastore['WIN_CONST']} filtering by #{datastore['WCREGEX'].to_s}")
		results = @rg.const_reverse_lookup(datastore['WIN_CONST'],datastore['WCREGEX'])
		print_status("RESULTS:  #{results.class} #{results.pretty_inspect}")
		
		print_status()
		print_status("TESTING:  error_lookup on #{datastore['ERR_CODE']} filtering by #{datastore['ECREGEX'].to_s}")
		results = @rg.error_lookup(datastore['ERR_CODE'],datastore['ECREGEX'])
		print_status("RESULTS:  #{results.class} #{results.inspect}")
		
		print_status()
		print_status("Testing Complete!")
	end
end


