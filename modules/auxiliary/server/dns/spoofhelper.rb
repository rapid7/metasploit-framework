##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'
require 'resolv'

module Msf

class Auxiliary::Server::Dns::SpoofHelper < Msf::Auxiliary

	include Auxiliary::Report

	
	def initialize
		super(
			'Name'        => 'DNS Spoofing Helper Service',
			'Version'     => '$Revision$',
			'Description'    => %q{
				This module provides a DNS service that returns TXT
			records indicating information about the querying service.
			Based on Dino Dai Zovi DNS code from Karma.
			
			},
			'Author'      => ['hdm', 'ddz'],
			'License'     => MSF_LICENSE,
			'Actions'     =>
				[
				 	[ 'Service' ]
				],
			'PassiveActions' => 
				[
					'Service'
				],
			'DefaultAction'  => 'Service'
		)

		register_options(
			[
				OptAddress.new('SRVHOST',   [ true, "The local host to listen on.", '0.0.0.0' ]),
				OptPort.new('SRVPORT',      [ true, "The local port to listen on.", 53 ]),
			], self.class)
	end

	
	def run		
		@targ = datastore['TARGETHOST']
		
		if(@targ and @targ.strip.length == 0)
			@targ = nil
		end

		@port = datastore['SRVPORT'].to_i

		# MacOS X workaround
		::Socket.do_not_reverse_lookup = true

		@sock = ::UDPSocket.new()
		@sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1)
		@sock.bind(datastore['SRVHOST'], @port)
		@run = true

		# Wrap in exception handler
		begin
			name = ''
			while @run
				packet, addr = @sock.recvfrom(65535)
				if (packet.length == 0)
					break
				end

				request = Resolv::DNS::Message.decode(packet)

				request.each_question {|name, typeclass|
					tc_s = typeclass.to_s().gsub(/^Resolv::DNS::Resource::/, "")

					request.qr = 1
					request.ra = 1

					case tc_s
					when 'IN::TXT'
						print_status("DNS #{addr[3]}:#{addr[1]} XID #{request.id} #{name}")						
						answer = Resolv::DNS::Resource::IN::TXT.new("#{addr[3]}:#{addr[1]} #{name}")
						request.add_answer(name, 1, answer)
					end
				}

				@sock.send(request.encode(), 0, addr[3], addr[1])
			end

		# Make sure the socket gets closed on exit
		rescue ::Exception => e
			print_error("spoofhelper: #{e.class} #{e} #{e.backtrace}")
		ensure
			@sock.close
		end
	end

end
end
