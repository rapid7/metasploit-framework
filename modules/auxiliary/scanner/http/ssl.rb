
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::WMAPScanServer
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	include Rex::Socket::Comm

	def initialize
		super(
			'Name'        => 'HTTP SSL Certificate Information',
			'Version'     => '$Revision$',
			'Description' => 'Parse the server SSL certificate to obtain the common name and signature algorithm',
			'Author'      => 'et',
			'License'     => MSF_LICENSE
		)
		register_options([
			Opt::RPORT(443)
		], self.class)

	end

	# Fingerprint a single host
	def run_host(ip)

		begin

			connect

			cert = OpenSSL::X509::Certificate.new(sock.peer_cert)

			disconnect

			if cert
				print_status("#{ip}:#{rport} Subject: #{cert.subject} Signature Alg: #{cert.signature_algorithm}")
				alg = cert.signature_algorithm

				if alg.downcase.include? "md5"
					print_status("#{ip}:#{rport} WARNING: Signature algorithm using MD5 (#{alg})")
				end

				vhostn = nil
				cert.subject.to_a.each do |n|
					vhostn = n[1] if n[0] == 'CN'
				end

				if vhostn
					print_status("#{ip}:#{rport} has common name #{vhostn}")

					# Store the virtual hostname for HTTP
					report_note(
						:host	=> ip,
						:port	=> rport,
						:proto  => 'tcp',
						:type	=> 'http.vhost',
						:data	=> {:name => vhostn}
					)

					# Store the SSL certificate itself
					report_note(
						:host	=> ip,
						:proto  => 'tcp',
						:port	=> rport,
						:type	=> 'ssl.certificate',
						:data	=> {
							:cn        => vhostn,
							:subject   => cert.subject.to_a,
							:algorithm => alg

						}
					)

					# Update the server hostname if necessary
					if vhostn !~ /localhost|snakeoil/i
						report_host(
							:host => ip,
							:name => vhostn
						)
					end

				end
			else
				print_status("#{ip}:#{rport}] No certificate subject or common name found")
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end

