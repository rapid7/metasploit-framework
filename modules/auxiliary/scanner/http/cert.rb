##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::WmapScanSSL
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'HTTP SSL Certificate Checker',
			'Author'      => 'nebulus',
			'License'     => MSF_LICENSE,
			'Description' => %q{
					This module will check the certificate of the specified web servers
				to ensure the subject and issuer match the supplied pattern and that the certificate
				is not expired.

				Note:  Be sure to check your expression if using msfcli, shells tend to not like certain
				things and will strip/interpret them (= is a perfect example). It is better to use in
				console.
			}
		)

		register_options(
			[
				Opt::RPORT(443),
				OptString.new('ISSUER', [ true,  "Show a warning if the Issuer doesn't match this regex", '.*']),
				OptBool.new('SHOWALL', [ false, "Show all certificates (issuer,time) regardless of match", false]),
			], self.class)
	end

	# Fingerprint a single host
	def run_host(ip)

		connect(true, {"SSL" => true}) #Force SSL
		cert  = OpenSSL::X509::Certificate.new(sock.peer_cert)
		disconnect

		if(not cert)
			print_status("#{ip} No certificate subject or CN found")
			return
		end

		issuer_pattern = Regexp.new(datastore['ISSUER'], [Regexp::EXTENDED, 'n'])
		sub = cert.subject.to_a

		before = Time.parse("#{cert.not_before}")
		after = Time.parse("#{cert.not_after}")

		now = Time.now
		a = now <=> before
		b = now <=> after

		vhostn = 'EMPTY'
		sub.each do |n|
			if n[0] == 'CN'
				vhostn = n[1]
			end
		end

		if ( "#{cert.issuer}" !~ /#{issuer_pattern}/)
			print_good("#{ip} - '#{vhostn}' : #{cert.issuer} (BAD ISSUER)" )
		elsif datastore['SHOWALL']
			# show verbose as status
			print_status("#{ip} - '#{vhostn}' : #{cert.issuer}")
		end

		if ( a < 1 or b > 0 )
			print_good("#{ip} - '#{vhostn}' : '" + before.to_s + "' - '" + after.to_s + "' (EXPIRED)'")
		elsif
			# show verbose as status
			print_status("#{ip} - '#{vhostn}' : '" + before.to_s + "' - '" + after.to_s + "'")
		end

		report_note(
			:host	=> ip,
			:port	=> rport,
			:proto  => 'tcp',
			:type	=> 'http.vhost',
			:data	=> {:name => vhostn}
		) if vhostn

		# Store the SSL certificate itself
		report_note(
			:host	=> ip,
			:proto  => 'tcp',
			:port	=> rport,
			:type	=> 'ssl.certificate',
			:data	=> {
				:cn        => vhostn,
				:subject   => cert.subject.to_a,
				:algorithm => cert.signature_algorithm

			}
		) if vhostn

		# Update the server hostname if necessary
		if vhostn !~ /localhost|snakeoil/i
			report_host(
				:host => ip,
				:name => vhostn
			)
		end


	rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
	rescue ::Timeout::Error, ::Errno::EPIPE
	rescue ::OpenSSL::SSL::SSLError => e
		return if(e.to_s.match(/^SSL_connect /) ) # strange errors / exception if SSL connection aborted
	rescue ::Exception => e
		return if(e.to_s =~ /execution expired/)
		print_error("Error: '#{ip}' '#{e.class}' '#{e}' '#{e.backtrace}'")
	end

end
