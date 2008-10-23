
##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'
require 'rex/socket/ssl_tcp'


class Metasploit3 < Msf::Auxiliary
	
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanServer
	include Msf::Auxiliary::Scanner
	
	include Rex::Socket::Comm

	def initialize
		super(
			'Name'        => 'HTTP SSL Certificate VHOST Detection',
			'Version'     => '$Revision$',
			'Description' => 'Display vhost associated to server using SSL certificate',
			'Author'      => 'et',
			'License'     => MSF_LICENSE
		)
		
	end

	# Fingerprint a single host
	def run_host(ip)


		begin
			ssock = Rex::Socket::SslTcp.create(
				'PeerHost' => ip,
				'PeerPort' => datastore['RPORT'])

			cert  = OpenSSL::X509::Certificate.new(ssock.peer_cert)

			ssock.close	
			
			if cert
				print_status("Subject: #{cert.subject.to_s}")
				sub = cert.subject.to_a
				
				sub.each do |n|
					if n[0] == 'CN'
						vhostn = n[1]
					end
				end

				vhostn = sub[sub.length-1][1]
			
				if vhostn
					print_status("#{ip} is host #{vhostn}")
				end
			else
				print_status("No certificate subject or CN found")
			end
			
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end

	end	
	
end

