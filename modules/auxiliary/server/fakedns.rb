##
# $Id: socks_unc.rb 5069 2007-08-08 02:46:31Z hdm $
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

class Auxiliary::Server::FakeDNS < Msf::Auxiliary

	include Auxiliary::Report

	
	def initialize
		super(
			'Name'        => 'Fake DNS Service',
			'Version'     => '$Revision: 5069 $',
			'Description'    => %q{
				This module provides a DNS service that redirects
			all queries to a particular address.
			},
			'Author'      => ['ddz', 'hdm'],
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
				OptString.new('TARGETHOST', [ false, "The address that all names should resolve to", nil ])
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
		
		Thread.new {
		# Wrap in exception handler
		begin
		
        while @run
            packet, addr = @sock.recvfrom(65535)
            if (packet.length == 0)
                break
            end
            request = Resolv::DNS::Message.decode(packet)
            
            #
            # XXX: Track request IDs by requesting IP address and port
            #
            # Windows XP SP1a: UDP source port constant, 
            #  sequential IDs since boot time
            # Windows XP SP2: Randomized IDs
            #
            # Debian 3.1: Static source port (32906) until timeout, 
            #  randomized IDs
            #
            log = "FakeDNS: #{addr[3]}:#{addr[1]} XID #{request.id} "
			lst = []
			
            request.each_question {|name, typeclass|
                tc_s = typeclass.to_s().gsub(/^Resolv::DNS::Resource::/, "")
                
                lst << "#{tc_s} #{name}"
				case tc_s
				when 'IN::A'
                    
                    # Special fingerprinting name lookups:
                    #
                    # _isatap -> XP SP = 0
                    # isatap.localdomain -> XP SP >= 1
                    # teredo.ipv6.microsoft.com -> XP SP >= 2
                    #
                    # time.windows.com -> windows ???
                    # wpad.localdomain -> windows ???
                    #
                    # <hostname> SOA -> windows XP self hostname lookup
                    #
                    
                    request.qr = 1
                    request.ra = 1
                    answer = Resolv::DNS::Resource::IN::A.new( @targ || ::Rex::Socket.source_address(addr[3].to_s) )
                    request.add_answer(name, 60, answer)
                
				when 'IN::MX'
                    request.qr = 1
                    request.ra = 1
                    mx = Resolv::DNS::Resource::IN::MX.new(10, Resolv::DNS::Name.create("mail.#{name}"))
                    ns = Resolv::DNS::Resource::IN::NS.new(Resolv::DNS::Name.create("dns.#{name}"))
					
					ar = Resolv::DNS::Resource::IN::A.new( @targ || ::Rex::Socket.source_address(addr[3].to_s) )

					request.add_answer(name, 60, mx)
					request.add_authority(name, 60, ns)	
					request.add_additional(Resolv::DNS::Name.create("mail.#{name}"), 60, ar)
					
				when 'IN::NS'
                    request.qr = 1
                    request.ra = 1
                    ns = Resolv::DNS::Resource::IN::NS.new(Resolv::DNS::Name.create("dns.#{name}"))
					ar = Resolv::DNS::Resource::IN::A.new( @targ || ::Rex::Socket.source_address(addr[3].to_s) )
					
					request.add_answer(name, 60, ns)
					request.add_additional(name, 60, ar)	
				else
					print_status("UNKNOWN #{tc_s}")		
				end
            }
			print_status("#{log} (#{lst.join(", ")})")
			
            @sock.send(request.encode(), 0, addr[3], addr[1])
        end
		
		# Make sure the socket gets closed on exit
		rescue ::Exception => e
			print_error("fakedns: #{e.class} #{e} #{e.backtrace}")
		ensure
			@sock.close
		end
		
		}
		
	end

end
end
