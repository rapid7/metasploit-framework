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

	include Msf::Exploit::Remote::MSSQL
	
	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Run simple SQL against the MSSQL instance',
			'Description'    => %q{
					This module will allow for simple SQL statements to be executed against a
					MSSQL/MSDE instance given the appropiate credentials.
			},
			'Author'         => [ 'tebo <tebo [at] attackresearch [dot] com>' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'URL', 'www.attackresearch.com' ],
					[ 'URL', 'http://msdn.microsoft.com/en-us/library/cc448435(PROT.10).aspx'],
				]))

			register_options( 
				[
					OptString.new('MSSQL_USER', [ false, 'The username to authenticate as', 'sa']),
					OptString.new('MSSQL_PASS', [ false, 'The password for the specified username', '']),
					OptString.new('SQL', [ false, 'The SQL to execute',  'select @@version']),
				], self.class)
	end

	def run
		connect
		if mssql_login(datastore['MSSQL_USER'], datastore['MSSQL_PASS'])
			query = datastore['SQL']
			res = sql_query(query)
		end
		disconnect
	end
end
