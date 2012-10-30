##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex/proto/dhcp'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name'		   => 'PXEBoot Enumerator',
			'Description'	=> %q{
				This module sends out BOOTP/DHCP requests and listens for 
				responses containing a PXEBoot response. Created to work with 
				Windows Deployment Services - other variants that work are a bonus...

			},
			'Author'		=> [ 'Ben Campbell <eat_meatballs@hotmail.co.uk>' ],
			'License'		=> MSF_LICENSE,
			'Version'		=> '$Revision$',
			'References' 	=>
				[
				]
			))

		register_options(
			[
				OptInt.new('WAIT', [ true, "Time to wait for responses", 5]),
				OptAddress.new('LHOST', [true, "Local host to listen on"]),
			], self.class)
	end

	def run
		wait = datastore['WAIT']
		@dhcp = Rex::Proto::DHCP::Client.new(datastore)
	
		@dhcp.report do |response|
			vprint_status("Response received from: #{response[:from][0]}")
		end
		

		print_status("Starting DHCP listener on 0.0.0.0...")
		@dhcp.start
		mac = "\x00\x50\x56\x35\x1a\x75"
		print_status("Sending Discovery packet waiting #{wait}s for responses...")
		@dhcp.send_packet(nil, @dhcp.create_discover(mac))
		@dhcp.thread.join(wait)
		@dhcp.stop
		num_responses = @dhcp.responses.length
		print_status("#{num_responses} response(s) received")
		

		if num_responses < 1
			print_error("No DHCP responses received, aborting...")
			return
		end

		yiaddr, pxeserver = parse_responses(@dhcp.responses)	

		# We cant bind to an IP/Listen on an IP that is not configured in the underlying OS
		# must rely on already having an IP assigned.
		#if yiaddr.nil? 
		#	print_error("No DHCP assignment received, aborting...") 
		#end

		yiaddr = datastore['LHOST']
	
		vprint_status("Rebinding listener to #{yiaddr}...")
		@dhcp.start(yiaddr)

		if pxeserver.nil?
			print_error("No PXEServer discovered, attempting a broadcast Request...")
			pxeserver = "255.255.255.255"
		end
		
		print_status("Sending Request Packet...")
		@dhcp.send_packet(pxeserver, @dhcp.create_request(mac, yiaddr), 4011)
		@dhcp.thread.join(wait)
		num_responses = @dhcp.responses.length
		print_status("#{num_responses} response(s) received.")

		if num_responses < 1
			return
		end

		parse_responses(@dhcp.responses)
	end

	def parse_responses(responses)
                yiaddr = nil
		pxeserver = nil

                responses.each do |response|
                        server = response[:from][0]
                        if response[:yiaddr] != '0.0.0.0'
                                yiaddr = response[:yiaddr]
                                vprint_status("Assigned IP #{yiaddr} by #{server}")
                        end
	
                        if !response[:filename].strip.empty?
                                if !response[:servhostname].strip.empty?                      
                                        pxeserver = response[:servhostname]
                                else
                                        pxeserver = server
                                end

                                print_good("PXE response from #{server} : #{pxeserver} : #{response[:filename]}")
                        end
			
			pxeclient = false
			dhcpserver = nil
			response[:dhcp_opts].each do |opt|
				option = opt[:opt]
				case option
				when Rex::Proto::DHCP::OpVendorClassID
					if opt[:val] == "PXEClient"
						pxeclient = true
						unless dhcpserver.nil?
							pxeserver = dhcpserver
						end
					end
				when Rex::Proto::DHCP::OpDHCPServer
					if pxeclient
						pxeserver = opt[:val]
					else
						dhcpserver = opt[:val]
					end
				end
			end                    
                end
		
		return yiaddr, pxeserver
		
	end

end
