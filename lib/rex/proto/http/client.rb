require 'rex/socket'
require 'rex/proto/http'
require 'rex/text'

module Rex
module Proto
module Http

###
#
# Acts as a client to an HTTP server, sending requests and receiving
# responses.
#
###
class Client

	#
	# Creates a new client instance
	#
	def initialize(host, port = 80, context = {}, ssl = nil, proxies = nil)
		self.hostname = host
		self.port     = port.to_i
		self.context  = context
		self.ssl      = ssl
		self.proxies  = proxies
		self.config = {
			'read_max_data'   => (1024*1024*1),
			'vhost'           => self.hostname,
			'version'         => '1.1',
			'agent'           => "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
			#
			# Evasion options
			#
			'uri_encode_mode'        => 'hex-normal', # hex-all, hex-random, u-normal, u-random, u-all
			'uri_encode_count'       => 1,       # integer
			'uri_full_url'           => false,   # bool
			'pad_method_uri_count'   => 1,       # integer
			'pad_uri_version_count'  => 1,       # integer
			'pad_method_uri_type'    => 'space', # space, tab, apache
			'pad_uri_version_type'   => 'space', # space, tab, apache
			'method_random_valid'    => false,   # bool
			'method_random_invalid'  => false,   # bool
			'method_random_case'     => false,   # bool
			'version_random_valid'   => false,   # bool
			'version_random_invalid' => false,   # bool
			'version_random_case'    => false,   # bool
			'uri_dir_self_reference' => false,   # bool
			'uri_dir_fake_relative'  => false,   # bool
			'uri_use_backslashes'    => false,   # bool
			'pad_fake_headers'       => false,   # bool
			'pad_fake_headers_count' => 16,      # integer
			'pad_get_params'         => false,   # bool
			'pad_get_params_count'   => 8,       # integer
			'pad_post_params'        => false,   # bool
			'pad_post_params_count'  => 8,       # integer
			'uri_fake_end'           => false,   # bool
			'uri_fake_params_start'  => false,   # bool
			'header_folding'         => false,   # bool 
			'chunked_size'           => 0        # integer
		}
		
		# This is not used right now...
		self.config_types = {
			'uri_encode_mode'        => ['hex-normal', 'hex-all', 'hex-random', 'u-normal', 'u-random', 'u-all'],
			'uri_encode_count'       => 'integer',
			'uri_full_url'           => 'bool',
			'pad_method_uri_count'   => 'integer',
			'pad_uri_version_count'  => 'integer',
			'pad_method_uri_type'    => ['space', 'tab', 'apache'],
			'pad_uri_version_type'   => ['space', 'tab', 'apache'],
			'method_random_valid'    => 'bool',
			'method_random_invalid'  => 'bool',
			'method_random_case'     => 'bool',
			'version_random_valid'   => 'bool',
			'version_random_invalid' => 'bool',
			'version_random_case'    => 'bool',
			'uri_dir_self_reference' => 'bool',
			'uri_dir_fake_relative'  => 'bool',
			'uri_use_backslashes'    => 'bool',
			'pad_fake_headers'       => 'bool',
			'pad_fake_headers_count' => 'integer',
			'pad_get_params'         => 'bool',
			'pad_get_params_count'   => 'integer',
			'pad_post_params'        => 'bool',
			'pad_post_params_count'  => 'integer',
			'uri_fake_end'           => 'bool',
			'uri_fake_params_start'  => 'bool',
			'header_folding'         => 'bool',
			'chunked_size'           => 'integer'
		}
	end
	
	#
	# Set configuration options
	#
	def set_config(opts = {})
		opts.each_pair do |var,val|
			self.config[var]=val
		end
	end
	
	#
	# Create an arbitrary HTTP request
	#
	def request_raw(opts={})
		c_enc  = opts['encode']     || false
		c_uri  = opts['uri']        || '/'
		c_body = opts['data']       || ''
		c_meth = opts['method']     || 'GET'
		c_prot = opts['proto']      || 'HTTP'		
		c_vers = opts['version']    || config['version'] || '1.1'
		c_qs   = opts['query']
		c_ag   = opts['agent']      || config['agent']
		c_cook = opts['cookie']     || config['cookie']
		c_host = opts['vhost']      || config['vhost']
		c_head = opts['headers']    || config['headers'] || {}
		c_rawh = opts['raw_headers']|| config['raw_headers'] || ''		
		c_conn = opts['connection']	
		c_auth = opts['basic_auth'] || config['basic_auth'] || ''
		
		uri    = set_uri(c_uri)
		
		req = ''
		req << set_method(c_meth)
		req << set_method_uri_spacer()
		req << set_uri_prepend()
		req << (c_enc ? set_encode_uri(uri) : uri)
		
		if (c_qs)
			req << '?'
			req << (c_enc ? set_encode_qs(c_qs) : c_qs)
		end
				
		req << set_uri_append()
		req << set_uri_version_spacer()
		req << set_version(c_prot, c_vers)
		req << set_host_header(c_host)
		req << set_agent_header(c_ag)

		if (c_auth.length > 0)
			req << set_basic_auth_header(c_auth)
		end
				
		req << set_cookie_header(c_cook)
		req << set_connection_header(c_conn)
		req << set_extra_headers(c_head)
		req << set_raw_headers(c_rawh)			
		req << set_body(c_body)
		
		req
	end

				
	#
	# Create a CGI compatible request
	#
	def request_cgi(opts={})
		c_enc  = opts['encode']     || false
		c_cgi  = opts['uri']        || '/'
		c_body = opts['data']       || ''
		c_meth = opts['method']     || 'GET'
		c_prot = opts['proto']      || 'HTTP'
		c_vers = opts['version']    || config['version'] || '1.1'
		c_qs   = opts['query']      || ''
		c_varg = opts['vars_get']   || {}
		c_varp = opts['vars_post']  || {}
		c_head = opts['headers']    || config['headers'] || {}
		c_rawh = opts['raw_headers']|| config['raw_headers'] || ''
		c_type = opts['ctype']      || 'application/x-www-form-urlencoded'
		c_ag   = opts['agent']      || config['agent']
		c_cook = opts['cookie']     || config['cookie']
		c_host = opts['vhost']      || config['vhost']
		c_conn = opts['connection']
		c_path = opts['path_info']
		c_auth = opts['basic_auth'] || config['basic_auth'] || ''

		uri    = set_cgi(c_cgi)
		qstr   = c_qs
		pstr   = c_body
		
		if (config['pad_get_params'])
			1.upto(config['pad_get_params_count'].to_i) do |i|
				qstr << '&' if qstr.length > 0
				qstr << set_encode_uri(Rex::Text.rand_text_alphanumeric(rand(32)+1))
				qstr << '='
				qstr << set_encode_uri(Rex::Text.rand_text_alphanumeric(rand(32)+1))			
			end
		end
		
		c_varg.each_pair do |var,val|
			qstr << '&' if qstr.length > 0
			qstr << set_encode_uri(var)
			qstr << '='
			qstr << set_encode_uri(val)
		end

		if (config['pad_post_params'])
			1.upto(config['pad_post_params_count'].to_i) do |i|
				pstr << '&' if qstr.length > 0
				pstr << set_encode_uri(Rex::Text.rand_text_alphanumeric(rand(32)+1))
				pstr << '='
				pstr << set_encode_uri(Rex::Text.rand_text_alphanumeric(rand(32)+1))			
			end
		end
		
		c_varp.each_pair do |var,val|
			pstr << '&' if pstr.length > 0
			pstr << set_encode_uri(var)
			pstr << '='
			pstr << set_encode_uri(val)
		end

		req = ''
		req << set_method(c_meth)
		req << set_method_uri_spacer()
		req << set_uri_prepend()
		req << (c_enc ? set_encode_uri(uri):uri)

		if (qstr.length > 0)
			req << '?'
			req << qstr
		end
		
		req << set_path_info(c_path)
		req << set_uri_append()
		req << set_uri_version_spacer()
		req << set_version(c_prot, c_vers)
		req << set_host_header(c_host)
		req << set_agent_header(c_ag)

		if (c_auth.length > 0)
			req << set_basic_auth_header(c_auth)
		end
				
		req << set_cookie_header(c_cook)
		req << set_connection_header(c_conn)		
		req << set_extra_headers(c_head)
			
		req << set_content_type_header(c_type)
		req << set_content_len_header(pstr.length)
		req << set_chunked_header()
		req << set_raw_headers(c_rawh)
		req << set_body(pstr)

		req	
	end	

	#
	# Connects to the remote server if possible.
	#
	def connect
		# If we already have a connection and we aren't pipelining, close it.
		if (self.conn)
			if !pipelining?
				close
			else
				return self.conn
			end
		end

		self.conn = Rex::Socket::Tcp.create(
			'PeerHost'  => self.hostname,
			'PeerPort'  => self.port.to_i,
			'LocalHost' => self.local_host,
			'LocalPort' => self.local_port,
			'Context'   => self.context,
			'SSL'       => self.ssl,
			'Proxies'   => self.proxies
		)
	end

	#
	# Closes the connection to the remote server.
	#
	def close
		if (self.conn)
			self.conn.shutdown
			self.conn.close 
		end

		self.conn = nil
	end

	#
	# Transmit a HTTP request and receive the response
	#
	def send_recv(req, t = -1)
		send_request(req)
		read_response(t)
	end

	#
	# Send a HTTP request to the server
	# TODO:
	#  * Handle junk pipeline requests
	def send_request(req) 
		# Connect to the server
		connect

		# build the request
		req_string = req.to_s

		# Send it on over
		ret = conn.put(req_string)

		ret
	end
	
	#
	# Read a response from the server
	#
	def read_response(t = -1)

		resp = Response.new
		resp.max_data = config['read_max_data']

		# Tell the remote side if we aren't pipelining
		#conn.shutdown(::Socket::SHUT_WR) if (!pipelining?)

		# Wait at most t seconds for the full response to be read in.  We only
		# do this if t was specified as a negative value indicating an infinite
		# wait cycle.  If t were specified as nil it would indicate that no
		# response parsing is required.
		timeout((t < 0) ? nil : t) {
			# Now, read in the response until we're good to go.
			begin
				if self.junk_pipeline
					i = 0
					self.junk_pipeline.times {
						i += 1
						rv = nil

						while rv != Packet::ParseCode::Completed
							if (rv == Packet::ParseCode::Error)
								raise RuntimeError, resp.error, caller
							end

							if resp.bufq.length > 0
								rv = resp.parse('')
							else
								rv = resp.parse(conn.get)
							end
						end

						if resp['Connection'] == 'close'
							raise RuntimeError, "junk pipelined request ##{i} caused the server to close the connection", caller
						end

						buf = resp.bufq
						resp.reset
						resp.bufq = buf
					}
				end

				rv = nil
				if resp.bufq.length > 0
					rv = resp.parse('')
				end

				if rv != Packet::ParseCode::Completed
					# Keep running until we finish parsing or EOF is reached
					while ((rv = resp.parse(conn.get)) != Packet::ParseCode::Completed)
						# Parsing error?  Raise an exception, our job is done.
						if (rv == Packet::ParseCode::Error)
							raise RuntimeError, resp.error, caller
						end
						select(nil, nil, nil, 0.10)
					end
				end
			rescue EOFError
				return nil
			rescue ::TimeoutError, ::Timeout::Error
				#$stdout.puts("timeout\n")
			end
		} if (t)

		# Close our side if we aren't pipelining
		#close if (!pipelining?)

		# if the server said stop pipelining, we listen... 
		if resp['Connection'] == 'close'
			#close
		end

		# XXX - How should we handle this?
		if (not resp.completed?)
			# raise RuntimeError, resp.error, caller
		end

		# Always return the Response object back to the client
		return resp
	end

	#
	# Cleans up any outstanding connections and other resources.
	#
	def stop
		close
	end

	#
	# Returns whether or not the conn is valid.
	#
	def conn?
		conn != nil
	end

	#
	# Whether or not connections should be pipelined.
	#
	def pipelining?
		pipeline
	end
	
	#
	# Return the encoded URI
	# ['none','hex-normal', 'hex-all', 'u-normal', 'u-all']
	def set_encode_uri(uri)	
		a = uri
		self.config['uri_encode_count'].times {
			a = Rex::Text.uri_encode(a, self.config['uri_encode_mode'])
		}
		return a
	end
	
	#
	# Return the encoded query string
	#
	def set_encode_qs(qs)
		a = qs 
		self.config['uri_encode_count'].times {
			a = Rex::Text.uri_encode(a, self.config['uri_encode_mode'])
		}
		return a
	end
	
	#
	# Return the uri
	#
	def set_uri(uri)
		
		if (self.config['uri_dir_self_reference'])
			uri.gsub!('/', '/./')
		end
		
		if (self.config['uri_dir_fake_relative'])
			buf = ""
			uri.split('/').each do |part|
				cnt = rand(8)+2
				1.upto(cnt) { |idx|
					buf << "/" + Rex::Text.rand_text_alphanumeric(rand(32)+1)
				}
				buf << ("/.." * cnt)
				buf << "/" + part
			end
			uri = buf
		end
			
		if (self.config['uri_full_url'])
			url = self.ssl ? "https" : "http"
			url << self.config['vhost']
			url << (self.port == 80) ? "" : ":#{self.port}"
			url << uri
			url
		else
			uri
		end
	end

	#
	# Return the cgi
	#
	def set_cgi(uri)

		if (self.config['uri_dir_self_reference'])
			uri.gsub!('/', '/./')
		end
		
		if (self.config['uri_dir_fake_relative'])
			buf = ""
			uri.split('/').each do |part|
				cnt = rand(8)+2
				1.upto(cnt) { |idx|
					buf << "/" + Rex::Text.rand_text_alphanumeric(rand(32)+1)
				}
				buf << ("/.." * cnt)
				buf << "/" + part
			end
			uri = buf
		end
			
		url = uri
	
		if (self.config['uri_full_url'])
			url = self.ssl ? "https" : "http"
			url << self.config['vhost']
			url << (self.port == 80) ? "" : ":#{self.port}"
			url << uri
		end
		
		url
	end
		
	#
	# Return the HTTP method string
	#
	def set_method(method)
		ret = method
		
		if (self.config['method_random_valid'])
			ret = ['GET', 'POST', 'HEAD'][rand(3)]
		end
		
		if (self.config['method_random_invalid'])
			ret = Rex::Text.rand_text_alpha(rand(20)+1)
		end
		
		if (self.config['method_random_case'])
			ret = Rex::Text.to_rand_case(ret)
		end
		
		ret
	end

	#
	# Return the HTTP version string
	#
	def set_version(protocol, version)
		ret = protocol + "/" + version
		
		if (self.config['version_random_valid'])
			ret = protocol + "/" +  ['1.0', '1.1'][rand(2)]
		end
		
		if (self.config['version_random_invalid'])
			ret = Rex::Text.rand_text_alphanumeric(rand(20)+1)
		end
		
		if (self.config['version_random_case'])
			ret = Rex::Text.to_rand_case(ret)
		end
		
		ret << "\r\n"
	end

	#
	# Return the HTTP seperator and body string
	#
	def set_body(data)
		return "\r\n" + data if self.config['chunked_size'] == 0
		str = data.dup
		chunked = ''
		while str.size > 0
			chunk = str.slice!(0,rand(self.config['chunked_size']) + 1)
			chunked << sprintf("%x", chunk.size) + "\r\n" + chunk + "\r\n"
		end
		"\r\n" + chunked + "0\r\n\r\n"
	end
	
	#
	# Return the HTTP path info
	# TODO:
	#  * Encode path information
	def set_path_info(path)
		path ? path : ''
	end
	
	#
	# Return the spacing between the method and uri
	#
	def set_method_uri_spacer
		len = self.config['pad_method_uri_count'].to_i
		set = " "
		buf = ""
		
		case self.config['pad_method_uri_type']
		when 'tab'
			set = "\t"
		when 'apache'
			set = "\t \x0b\x0c\x0d"
		end
		
		while(buf.length < len)
			buf << set[ rand(set.length) ]
		end
		
		return buf
	end

	#
	# Return the spacing between the uri and the version
	#
	def set_uri_version_spacer
		len = self.config['pad_uri_version_count'].to_i
		set = " "
		buf = ""
		
		case self.config['pad_uri_version_type']
		when 'tab'
			set = "\t"
		when 'apache'
			set = "\t \x0b\x0c\x0d"
		end
		
		while(buf.length < len)
			buf << set[ rand(set.length) ]
		end
		
		return buf
	end

	#
	# Return the padding to place before the uri
	#
	def set_uri_prepend
		prefix = ""
		
		if (self.config['uri_fake_params_start'])
			prefix << '/%3fa=b/../'
		end
		
		if (self.config['uri_fake_end'])
			prefix << '/%20HTTP/1.0/../../'
		end
		
		prefix
	end

	#
	# Return the padding to place before the uri
	#
	def set_uri_append
		# TODO:
		#  * Support different padding types
		""
	end

	#
	# Return the HTTP Host header
	#
	def set_host_header(host)
		return "" if self.config['uri_full_url']
		host ||= self.config['vhost']
		set_formatted_header("Host", host)
	end

	#
	# Return the HTTP agent header
	#
	def set_agent_header(agent)		
		agent ? set_formatted_header("User-Agent", agent) : ""
	end

	#
	# Return the HTTP cookie header
	#
	def set_cookie_header(cookie)
		cookie ? set_formatted_header("Cookie", cookie) : ""
	end

	#
	# Return the HTTP connection header
	#
	def set_connection_header(conn)
		conn ? set_formatted_header("Connection", conn) : ""				
	end
		
	#
	# Return the content type header
	#
	def set_content_type_header(ctype)
		set_formatted_header("Content-Type", ctype)
	end

	#
	# Return the content length header
	def set_content_len_header(clen)
		return "" if self.config['chunked_size'] > 0
		set_formatted_header("Content-Length", clen)
	end

	#
	# Return the Authorization basic-auth header
	#
	def set_basic_auth_header(auth)
		auth ? set_formatted_header("Authorization", "Basic " + Rex::Text.encode_base64(auth)) : ""
	end

	#
	# Return a string of formatted extra headers
	#
	def set_extra_headers(headers)
		buf = ''

		if (self.config['pad_fake_headers'])
			1.upto(self.config['pad_fake_headers_count'].to_i) do |i|
				buf << set_formatted_header(
					Rex::Text.rand_text_alphanumeric(rand(32)+1), 
					Rex::Text.rand_text_alphanumeric(rand(32)+1)
				)
			end
		end

		headers.each_pair do |var,val|
			buf << set_formatted_header(var, val)
		end
		
		buf
	end

	def set_chunked_header()
		return "" if self.config['chunked_size'] == 0
		set_formatted_header('Transfer-Encoding', 'chunked')
	end

	#
	# Return a string of raw header data
	#
	def set_raw_headers(data)
		data
	end
		
	#
	# Return a formatted header string
	#
	def set_formatted_header(var, val)
		if (self.config['header_folding'])
			"#{var}:\r\n\t#{val}\r\n"
		else
			"#{var}: #{val}\r\n"
		end
	end
	


	#
	# The client request configuration
	#
	attr_accessor :config
	#
	# The client request configuration classes
	#
	attr_accessor :config_types
	#
	# Whether or not pipelining is in use.
	#
	attr_accessor :pipeline
	#
	# The local host of the client.
	#
	attr_accessor :local_host
	#
	# The local port of the client.
	#
	attr_accessor :local_port
	#
	# The underlying connection.
	#
	attr_accessor :conn
	#
	# The calling context to pass to the socket
	#
	attr_accessor :context
	#
	# The proxy list
	#
	attr_accessor :proxies
	

	# When parsing the request, thunk off the first response from the server, since junk
	attr_accessor :junk_pipeline
	
protected

	# https
	attr_accessor :ssl

	attr_accessor :hostname, :port # :nodoc:

	
end

end
end
end
