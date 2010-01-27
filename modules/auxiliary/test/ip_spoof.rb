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
require 'racket'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Capture
	include Msf::Auxiliary::Scanner
		
	def initialize
		super(
			'Name'        => 'Simple IP Spoofing Tester',
			'Version'     => '$Revision$',
			'Description' => 'Simple IP Spoofing Tester',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)

		begin
			require 'pcaprub'
			@@havepcap = true
		rescue ::LoadError
			@@havepcap = false
		end

		deregister_options('FILTER','PCAPFILE')

	end

	def run_host(ip)
		open_pcap
		n = Racket::Racket.new

		n.l3 = Racket::L3::IPv4.new
		n.l3.src_ip = ip
		n.l3.dst_ip = ip
		n.l3.protocol = 17
		n.l3.id = 0xdead
		n.l3.ttl = 255
				
		n.l4 = Racket::L4::UDP.new
		n.l4.src_port = 53
		n.l4.dst_port = 53
		n.l4.payload  = "HELLO WORLD"
		
		n.l4.fix!(n.l3.src_ip, n.l3.dst_ip)	
	
		buff = n.pack
		ret = send(ip,buff)
		if ret == :done
			print_good("#{ip}: Sent a packet to #{ip} from #{ip}")
		else
			print_error("#{ip}: Packet not sent. Check permissions & interface.")
		end
		close_pcap
	end

	def send(ip,buff)
		begin
			capture_sendto(buff, ip)
		rescue RuntimeError => e
			return :error
		end
		return :done
	end

	
end
