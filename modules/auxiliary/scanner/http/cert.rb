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

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::WMAPScanServer
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'HTTP SSL Certificate Checker',
			'Version'     => '$Revision$',
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

		connect
		cert  = OpenSSL::X509::Certificate.new(sock.peer_cert)
		disconnect

		if(not cert)
			print_status("#{ip} No certificate subject or CN found")
			return
		end

		issuer_pattern = Regexp.new(datastore['ISSUER'], [Regexp::EXTENDED, 'n'])
		sub = cert.subject.to_a

		before_d = "#{cert.not_before}".split
		if(! before_d[1] =~ /\d\d\:\d\d:\d\d/ or ! before_d[0] =~ /\d{2,4}\-\d\d-\d\d/)
		# this is here out of concerns that the time / date format may vary
			print_error("#{ip} - WARNING: Unexpected before date! " + before_d.inspect)
			return
		end

		before_t = before_d[1].split(":")	# get hh:mm:ss
		before_d = before_d[0].split('-')	# get yyyy-mm-dd

		after_d = "#{cert.not_after}".split
		if(! after_d[1] =~ /\d\d\:\d\d:\d\d/ or ! after_d[0] =~ /\d{2,4}\-\d\d-\d\d/)
		# this is here out of concerns that the time / date format may vary
			print_error("#{ip} - WARNING: Unexpected after date! " + after_d.inspect)
			return
		end

		after_t = after_d[1].split(":")		# get hh:mm:ss
		after_d = after_d[0].split('-')		# get yyyy-mm-dd


		before = Time.utc(before_d[0],before_d[1],before_d[2],before_t[0],before_t[1],before_t[2])
		after = Time.utc(after_d[0],after_d[1],after_d[2],after_t[0],after_t[1],after_t[2])

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
			print_error("#{ip} - '#{vhostn}' : #{cert.issuer} (BAD ISSUER)" )
		elsif datastore['SHOWALL']
			# show verbose as status
			print_good("#{ip} - '#{vhostn}' : #{cert.issuer}")
		end

		if ( a < 1 or b > 0 )
			print_error("#{ip} - '#{vhostn}' : '" + before.to_s + "' - '" + after.to_s + "' (EXPIRED)'")
		elsif
			# show verbose as status
			print_good("#{ip} - '#{vhostn}' : '" + before.to_s + "' A- '" + after.to_s + "'")
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
