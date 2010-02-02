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


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Postgres
	
	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'PostgreSQL Server Generic Query',
			'Description'    => %q{
					This module will allow for simple SQL statements to be executed against a
					PostgreSQL instance given the appropiate credentials.
			},
			'Author'         => [ 'todb' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'URL', 'www.postgresql.org' ]
				],
			'Version'        => '$Revision$'
		))

		register_options( [ ], self.class) # None needed. 
	end

	def rhost
		datastore['RHOST']
	end

	def rport
		datastore['RPORT']
	end
	
	def run
		postgres_query(datastore['SQL'],datastore['RETURN_ROWSET'])
		postgres_logout if self.postgres_conn
	end
end
