##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex/proto/natpmp'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'NAT-PMP Port Mapper',
			'Description' => 'Map (forward) TCP and UDP ports on NAT devices using NAT-PMP',
			'Author'      => 'Jon Hart <jhart[at]spoofed.org>',
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::LPORT,
				Opt::RPORT,
				OptInt.new('NATPMPPORT', [true, "NAT-PMP port to use", Rex::Proto::NATPMP::DefaultPort]),
				OptInt.new('LIFETIME', [true, "Time in ms to keep this port forwarded", 3600000]),
				OptEnum.new('PROTOCOL', [true, "Protocol to forward", 'TCP', %w(TCP UDP)]),
				Opt::CHOST
			],
			self.class
		)
	end

	def run_host(host)
		begin

			udp_sock = Rex::Socket::Udp.create({
				'LocalHost' => datastore['CHOST'] || nil,
				'Context'   => {'Msf' => framework, 'MsfExploit' => self}
			})
			add_socket(udp_sock)

			# get the external address first
			vprint_status "#{host} - NATPMP - Probing for external address"
			req = Rex::Proto::NATPMP.external_address_request
			udp_sock.sendto(req, host, datastore['NATPMPPORT'], 0)
			external_address = nil
			while (r = udp_sock.recvfrom(12, 1) and r[1])
				(ver, op, result, epoch, external_address) = Rex::Proto::NATPMP.parse_external_address_response(r[0])
			end

			vprint_status "#{host} - NATPMP - Sending mapping request"
			# build the mapping request
			req = Rex::Proto::NATPMP.map_port_request(
					datastore['LPORT'].to_i, datastore['RPORT'].to_i,
					Rex::Proto::NATPMP.const_get(datastore['PROTOCOL']), datastore['LIFETIME']
			)
			# send it
			udp_sock.sendto(req, host, datastore['NATPMPPORT'], 0)
			# handle the reply
			while (r = udp_sock.recvfrom(16, 1) and r[1])
				handle_reply(Rex::Socket.source_address(host), host, external_address, r)
			end
		rescue ::Interrupt
			raise $!
		rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
			nil
		rescue ::Exception => e
			print_error("Unknown error: #{e.class} #{e.backtrace}")
		end
	end

	def handle_reply(map_target, host, external_address, pkt)
		return if not pkt[1]

		if(pkt[1] =~ /^::ffff:/)
			pkt[1] = pkt[1].sub(/^::ffff:/, '')
		end

		(ver, op, result, epoch, internal_port, external_port, lifetime) = Rex::Proto::NATPMP.parse_map_port_response(pkt[0])

		if (result == 0)
			if (datastore['RPORT'].to_i != external_port)
				print_status(	"#{external_address} " +
								"#{datastore['RPORT']}/#{datastore['PROTOCOL']} -> #{map_target} " +
								"#{internal_port}/#{datastore['PROTOCOL']} couldn't be forwarded")
			end
			print_status(	"#{external_address} " +
							"#{external_port}/#{datastore['PROTOCOL']} -> #{map_target} " +
							"#{internal_port}/#{datastore['PROTOCOL']} forwarded")
		end

		# report NAT-PMP as being open
		report_service(
			:host   => host,
			:port   => pkt[2],
			:proto  => 'udp',
			:name  => 'natpmp',
			:state => Msf::ServiceState::Open
		)

		# report the external port as being open
		if inside_workspace_boundary(external_address)
			report_service(
				:host   => external_address,
				:port   => external_port,
				:proto  => datastore['PROTOCOL'].to_s.downcase,
				:state => Msf::ServiceState::Open
			)
		end
	end
end
