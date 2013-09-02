##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/netapi'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::NetAPI

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
		domains = net_server_enum(SV_TYPE_DOMAIN_ENUM)

		domains.each do |domain|
			print_status("Enumerating DCs for #{domain[:name]}")
			dcs = net_server_enum(SV_TYPE_DOMAIN_BAKCTRL | SV_TYPE_DOMAIN_CTRL, domain[:name])

			if dcs.count == 0
				print_error("No Domain Controllers found...")
				next
			end

			dcs.each do |dc|
				print_good("Domain Controller: #{dc[:name]}")

				report_note(
					:host   => session,
					:type   => 'domain.hostnames',
					:data   => dc[:name],
					:update => :unique_data
				)
			end
		end
	end
end
