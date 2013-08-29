##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Multi Generic Operating System Session Command Execution',
			'Description'   => %q{ This module executes an arbitrary command line},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'hdm' ],
			'Platform'      => [ 'linux', 'win', 'unix', 'osx' ],
			'SessionTypes'  => [ 'shell', 'meterpreter' ]
		))
		register_options(
			[
				OptString.new( 'COMMAND', [false, 'The entire command line to execute on the session'])
			], self.class)
	end

	def run
		print_status("Executing #{datastore['COMMAND']} on #{session.inspect}...")
		res = cmd_exec(datastore['COMMAND'])
		print_status("Response: #{res}")

	end

end
