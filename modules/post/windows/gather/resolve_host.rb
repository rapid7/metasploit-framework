#
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
			'Name'          => 'Windows Gather Domain Enumeration',
			'Description'   => %q{
				This module enumerates currently the domains a host can see and the domain
				controllers for that domain.
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'mubix' ],
			'Platform'      => [ 'win' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))
	end

	def run
		host = "google.com"
		#response = client.net.resolve.hostname_to_ipv4(host)
		response = client.net.resolve.resolve_host(host)
		p response
		hosts = []
		hosts << "localhost"
		hosts << "google.com"
		hosts << "ipv6.cybernode.com"
		hosts << "definitelyunknownaddr.com"


		response = client.net.resolve.resolve_hosts(hosts)
		p response
	end
end
