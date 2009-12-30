
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'rex/socket/ssl_tcp'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::WMAPScanServer
	include Msf::Auxiliary::Scanner

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
			}
		)

		register_options(
		[
			Opt::RPORT(443),
			OptString.new('ISSUER', [ true,  "Show a warning if the Issuer doesn't match this regex", '.*']),
			OptBool.new('SHOWALL', [ false, "Show all certificates regardless of match", false]),
		], self.class)
	end

	# Fingerprint a single host
	def run_host(ip)

		begin
			ssock = connect(false, {'SSL' => true})
			cert  = OpenSSL::X509::Certificate.new(ssock.peer_cert)
			ssock.close

			if(not cert)
				print_status("#{ip} No certificate subject or CN found")
				return
			end

			issuer_pattern = Regexp.new(datastore['ISSUER'], Regexp::EXTENDED, 'n')
			sub = cert.subject.to_a

			before_d = "#{cert.not_before}".split
			before_t = before_d[3].split(":")
			after_d = "#{cert.not_after}".split
			after_t = after_d[3].split(":")
			before = Time.utc(before_d[5],before_d[1],before_d[2],before_t[0],before_t[1],before_t[3])
			after = Time.utc(after_d[5],after_d[1],after_d[2],after_t[0],after_t[1],after_t[3])

			now = Time.now
			a = now <=> before
			b = now <=> after

			vhostn = 'EMPTY'
			sub.each do |n|
				if n[0] == 'CN'
					vhostn = n[1]
				end
			end

			if ( not "#{cert.issuer}" =~ /#{issuer_pattern}/)
				print_status("WARNING (Issuer): #{ip} / #{vhostn} : #{cert.issuer}" )
			end
			print_status("#{ip} / #{vhostn} Issuer: #{cert.issuer}") if datastore['SHOWALL']

			if ( a < 1 or b > 0 )
				print_status("WARNING (Expired): #{ip} / #{vhostn} : Cert is expired/invalid: Before: " + before.to_s + " After " + after.to_s)
			end
			print_status("#{ip} / #{vhostn} Before: " + before.to_s + " After: " + after.to_s + " Now: " + now.to_s)  if datastore['SHOWALL']

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end

end

