##
# $Id:
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::SunRPC
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'          => 'NFS Mount Scanner',
			'Description'   => %q{
				This module scans NFS mounts and their permissions.
			},	
			'Author'	    => ['<tebo [at] attackresearch.com>'],
			'References'	=>
				[
					['URL',	'http://www.ietf.org/rfc/rfc1094.txt'],
				],
			'License'	=> MSF_LICENSE
		)

		register_options([
			OptString.new('HOSTNAME', [false, 'Remote hostname', 'localhost']),
			OptInt.new('GID', [false, 'GID to emulate', 0]),
			OptInt.new('UID', [false, 'UID to emulate', 0])
		], self.class)
	end

	def run_host(ip)

		begin

			hostname	= datastore['HOSTNAME']
			program		= 100005
			progver		= 1
			procedure	= 1

			sunrpc_create('udp', program, progver)
			sunrpc_authunix(hostname, datastore['UID'], datastore['GID'], [])
			resp = sunrpc_call(5, "")
      
			exports = resp[3,1].unpack('C')[0]
			if (exports == 0x01)
				print_good("#{ip} - Exports found")
				while XDR.decode_int!(resp) == 1 do
					dir = XDR.decode_string!(resp)
					grp = []
					while XDR.decode_int!(resp) == 1 do
						grp << XDR.decode_string!(resp)
					end
					print_line("\t#{dir}\t[#{grp.join(", ")}]")
				end
			elsif(exports == 0x00)
				print_status("#{ip} - No exports")
			end
      
			sunrpc_destroy	
		rescue ::Rex::Proto::SunRPC::RPCTimeout
		end
	end

end
