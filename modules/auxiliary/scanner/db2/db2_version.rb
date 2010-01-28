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
		register_options(
			[
				OptBool.new('VERBOSE', [ true, 'Verbose output', false])
		], self.class)

		deregister_options('USERNAME' , 'PASSWORD')
	end


	def run_host(ip)
		verbose = datastore['VERBOSE']
		begin
		
			info = db2_probe(2)
			if info[:excsatrd]
				inst,plat,ver,pta = info[:instance_name],info[:platform],info[:version],info[:plaintext_auth]
				report_info = "#{plat} : #{ver} : #{inst} : PlainAuth-#{pta ? "OK" : "NO"}"
				print_status("#{ip}:#{rport} [DB2] #{report_info}")
				report_service(:host => rhost, 
					:port => rport,
					:name => "db2",
					:info => report_info)
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
