
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
			'Name'        => 'HTTP SSL Certificate tester',
			'Version'     => '$Revision: 6022 $',
			'Description' => 'Display vhost associated to server using SSL certificate and check for signature algorithm',
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
				print_status("Subject: #{cert.subject} Signature Alg: #{cert.signature_algorithm}")
				alg = cert.signature_algorithm
				
				if alg.downcase.include? "md5"
					print_status("#{ip} WARNING: Signature algorithm using MD5 (#{alg})")
				end
				
				sub = cert.subject.to_a
				
				vhostn = 'EMPTY' 
				sub.each do |n|
					#print_line "#{n[0]}"
					if n[0] == 'CN'
						#print_line "> #{n[1]}"
						vhostn = n[1]
					end
				end
			
				if vhostn
					print_status("#{ip} is host #{vhostn}")
					rep_id = wmap_base_report_id(
										wmap_target_host,
										wmap_target_port,
										wmap_target_ssl
								)
								
					wmap_report(rep_id,'VHOST','NAME',"#{vhostn}","Vhost #{vhostn} found.")
					wmap_report(rep_id,'X509','SUBJECT',"#{cert.subject}",nil)
					wmap_report(rep_id,'X509','SIGN_ALGORITHM',"#{cert.signature_algorithm}","Signature algorithm")
				end
			else
				print_status("No certificate subject or CN found")
			end
			
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end

	end	
	
end

