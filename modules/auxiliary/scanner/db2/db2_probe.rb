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
        
	include Msf::Exploit::Remote::Tcp
	include Msf::Exploit::Remote::DB2
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
	
	def initialize
		super(
			'Name'           => 'DB2 Probe Utility',
			'Version'        => '$Revision$',
			'Description'    => 'This module queries a DB2 instance information.',
			'Author'         => ['todb'],
			'License'        => MSF_LICENSE
		)

		deregister_options('USERNAME' , 'PASSWORD')
	end


	def run_host(ip)
		begin
		
			info = db2_probe(2)
			if info[:excsatrd]
				print_status("DB2 Server information for #{ip}:")
				print_status("    Instance          = #{info[:instance_name]}")
				print_status("    Platform          = #{info[:platform]}")
				print_status("    Version           = #{info[:version]}")
				print_status("    Plaintext Auth?   = #{info[:plaintext_auth]}")
			end
			disconnect
		
		rescue ::Rex::ConnectionError
			print_error("#{rhost}:#{rport} : Unable to attempt probe") if verbose 
			return :done
		rescue ::Rex::Proto::DRDA::RespError => e
			print_error("#{rhost}:#{rport} : Error in connecting to DB2 instance: #{e}") if verbose 
			return :error
		end
	end
end
