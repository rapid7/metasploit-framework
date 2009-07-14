##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::ORACLE
	
	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Run simple SQL against the Oracle instance.',
			'Description'    => %q{
					This module allows for simple sql to be executed against a given
					oracle instance.
			},
			'Author'         => [ 'MC' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision:$',
			'References'     =>
				[
					[ 'URL', 'https://www.metasploit.com/users/mc' ],
				],
			'DisclosureDate' => 'Dec 7 2007'))

			register_options( 
				[
					OptString.new('SQL', [ false, 'The SQL to execute.',  'select * from v$version']),
				], self.class)
	end

	def run
		query = datastore['SQL']

		begin
			print_status("Sending statement: '#{query}'...")	
			prepare_exec(query)
		rescue => e
			return			
		end
	end

end
