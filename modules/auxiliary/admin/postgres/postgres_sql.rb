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
				]
		))

		register_options( 
			[
				OptString.new('SQL', [ false, 'The SQL query to execute',  'select version()']),
			], self.class)
	end
	
	def run
		postgres_query(datastore['SQL'], true)
		postgres_logout if self.postgres_conn
	end
end
