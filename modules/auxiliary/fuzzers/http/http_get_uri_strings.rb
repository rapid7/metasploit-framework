##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Fuzzer

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'HTTP GET Request URI Fuzzer (Fuzzer Strings)',
			'Description'    => %q{
				This module sends a series of HTTP GET request with malicious URIs.
			},
			'Author'         => [ 'nullthreat' ],
			'License'        => MSF_LICENSE
		))
		register_options([
			Opt::RPORT(80),
			OptString.new("VHOST", [false, "The virtual host name to use in requests"]),
			OptString.new("URIBASE", [true, "The base URL to use for the request fuzzer", "/"])
		], self.class)
	end

	def do_http_get(uri='',opts={})
		@connected = false
		connect
		@connected = true

		sock.put("GET #{uri} HTTP/1.1\r\nHost: #{datastore['VHOST'] || rhost}\r\n\r\n")
		sock.get_once(-1, opts[:timeout] || 0.01)
	end

	def run
		last_str = nil
		last_inp = nil
		last_err = nil

		pre = make_http_uri_base
		cnt = 0

		fuzz_strings do |str|
			cnt += 1

			# XXX: Encode the string or leave it raw? Best to make a new boolean option to enable/disable this
			uri = pre + str

			if(cnt % 100 == 0)
				print_status("Fuzzing with iteration #{cnt} using #{@last_fuzzer_input}")
			end

			begin
				r = do_http_get(uri,:timeout => 0.50)
			rescue ::Interrupt
				print_status("Exiting on interrupt: iteration #{cnt} using #{@last_fuzzer_input}")
				raise $!
			rescue ::Exception => e
				last_err = e
			ensure
				disconnect
			end

			if(not @connected)
				if(last_str)
					print_status("The service may have crashed: iteration:#{cnt-1} method=#{last_inp} uri=''#{last_str}'' error=#{last_err}")
				else
					print_status("Could not connect to the service: #{last_err}")
				end
				return
			end

			last_str = str
			last_inp = @last_fuzzer_input
		end
	end

	def make_http_uri_base
		datastore['URIBASE']
	end
end
