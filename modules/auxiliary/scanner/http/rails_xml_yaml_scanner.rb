##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner

	def initialize(info={})
		super(update_info(info,
			'Name'        => 'Ruby on Rails XML Processor YAML Deserialization Scanner',
			'Description' => %q{
				This module attempts to identify Ruby on Rails instances vulnerable to
				an arbitrary object instantiation flaw in the XML request processor.
			},
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE,
			'References'  =>
				[
					['CVE', '2013-0156'],
					['URL', 'https://community.rapid7.com/community/metasploit/blog/2013/01/09/serialization-mischief-in-ruby-land-cve-2013-0156']
				]
		))

		register_options([
			OptString.new('URIPATH', [true, "The URI to test", "/"])
		], self.class)
	end

	def send_probe(ptype, pdata)
		odata = %Q^<?xml version="1.0" encoding="UTF-8"?>\n<probe type="#{ptype}"><![CDATA[\n#{pdata}\n]]></probe>^
		res = send_request_cgi({
			'uri'    => datastore['URIPATH'] || "/",
			'method' => 'POST',
			'ctype'  => 'application/xml',
			'data'   => odata
		}, 25)
	end

	def run_host(ip)

		res1 = send_probe("string", "hello")
		res2 = send_probe("yaml", "--- !ruby/object:Time {}\n")
		res3 = send_probe("yaml", "--- !ruby/object:\x00")

		unless res1
			vprint_status("#{rhost}:#{rport} No reply to the initial XML request")
			return
		end

		unless res2
			vprint_status("#{rhost}:#{rport} No reply to the initial YAML probe")
			return
		end

		unless res3
			vprint_status("#{rhost}:#{rport} No reply to the second YAML probe")
			return
		end

		if res1.code.to_s =~ /^[45]/
			vprint_status("#{rhost}:#{rport} The server replied with #{res1.code} for our initial XML request, double check URIPATH")
		end

		if res2.code.to_s =~ /^[23]/ and res3.code != res2.code and res3.code != 200
			print_good("#{rhost}:#{rport} is likely vulnerable due to a #{res3.code} reply for invalid YAML")
			report_vuln({
				:host	=> rhost,
				:port	=> rport,
				:proto  => 'tcp',
				:name	=> self.name,
				:info	=> "Module triggered a #{res3.code} reply",
				:refs   => self.references
			})
		else
			vprint_status("#{rhost}:#{rport} is not likely to be vulnerable or URIPATH must be set")
		end
	end

end
