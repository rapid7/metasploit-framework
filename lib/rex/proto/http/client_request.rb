# -*- coding: binary -*-
require 'uri'
require 'rex/proto/http'


module Rex
module Proto
module Http

class ClientRequest

	attr_accessor :authorization
	attr_accessor :cgi
	attr_accessor :config
	attr_accessor :connection
	attr_accessor :content_type
	attr_accessor :cookie
	attr_accessor :data
	attr_accessor :encode
	attr_accessor :encode_params
	attr_accessor :headers
	attr_accessor :host
	attr_accessor :method
	attr_accessor :path
	attr_accessor :port
	attr_accessor :protocol
	attr_accessor :query
	attr_accessor :raw_headers
	attr_accessor :ssl
	attr_accessor :uri
	attr_accessor :user_agent
	attr_accessor :vars_get
	attr_accessor :vars_post
	attr_accessor :version

	attr_reader :opts

	def initialize(opts={})
		@config        = opts['client_config'] || {}
		@connection    = opts['connection']
		@content_type  = opts['ctype']
		@cookie        = opts['cookie']
		@data          = opts['data']        || ""
		@encode        = opts['encode']
		@encode_params = opts['encode_params']
		@headers       = opts['headers']     || {}
		@host          = opts['vhost']
		@method        = opts['method']      || "GET"
		@path          = opts['path_info']
		@port          = opts['port']        || 80
		@protocol      = opts['proto']       || "HTTP"
		@query         = opts['query']       || ""
		@ssl           = opts['ssl']         || false
		@raw_headers   = opts['raw_headers'] || ""
		@uri           = opts['uri']
		@user_agent    = opts['agent']
		@vars_get      = opts['vars_get']
		@vars_post     = opts['vars_post']
		@version       = opts['version']
		@opts = opts

		config['chunked_size'] ||= 0
		config['pad_method_uri_count'] ||= 1
	end

	def to_s

		#  Start GET query string
		qstr = query

		# Start POST data string
		pstr = data

		if cgi == true
			uri_str= set_cgi

			if (config['pad_get_params'])
				1.upto(config['pad_get_params_count'].to_i) do |i|
					qstr << '&' if qstr.length > 0
					qstr << set_encode_uri(Rex::Text.rand_text_alphanumeric(rand(32)+1))
					qstr << '='
					qstr << set_encode_uri(Rex::Text.rand_text_alphanumeric(rand(32)+1))
				end
			end

			vars_get.each_pair do |var,val|
				qstr << '&' if qstr.length > 0
				qstr << (encode_params ? set_encode_uri(var) : var)
				qstr << '='
				qstr << (encode_params ? set_encode_uri(val) : val)
			end

			if (config['pad_post_params'])
				1.upto(config['pad_post_params_count'].to_i) do |i|
					rand_var = Rex::Text.rand_text_alphanumeric(rand(32)+1)
					rand_val = Rex::Text.rand_text_alphanumeric(rand(32)+1)
					pstr << '&' if pstr.length > 0
					pstr << (encode_params ? set_encode_uri(rand_var) : rand_var)
					pstr << '='
					pstr << (encode_params ? set_encode_uri(rand_val) : rand_val)
				end
			end

			vars_post.each_pair do |var,val|
				pstr << '&' if pstr.length > 0
				pstr << (encode_params ? set_encode_uri(var) : var)
				pstr << '='
				pstr << (encode_params ? set_encode_uri(val) : val)
			end
		else
			uri_str = set_uri
			if encode
				qstr = set_encode_uri(qstr)
			end
		end

		req = ''
		req << set_method
		req << set_method_uri_spacer()
		req << set_uri_prepend()

		if  encode
			req << set_encode_uri(uri_str)
		else
			req << uri_str
		end


		if (qstr.length > 0)
			req << '?'
			req << qstr
		end

		req << set_path_info
		req << set_uri_append()
		req << set_uri_version_spacer()
		req << set_version
		req << set_host_header

		# If an explicit User-Agent header is set, then use that instead of the value of user_agent
		unless headers.keys.map{|x| x.downcase }.include?('user-agent')
			req << set_agent_header
		end

		if authorization
			req << set_auth_header
		end

		req << set_cookie_header
		req << set_connection_header
		req << set_extra_headers

		req << set_content_type_header
		req << set_content_len_header(pstr.length)
		req << set_chunked_header()
		req << raw_headers
		req << set_body(pstr)
	end

	protected

	def set_auth_header
		"Authorization: " + authorization
	end

	def set_uri
		uri_str = uri.dup
		if (config['uri_dir_self_reference'])
			uri_str.gsub!('/', '/./')
		end

		if (config['uri_dir_fake_relative'])
			buf = ""
			uri_str.split('/').each do |part|
				cnt = rand(8)+2
				1.upto(cnt) { |idx|
					buf << "/" + Rex::Text.rand_text_alphanumeric(rand(32)+1)
				}
				buf << ("/.." * cnt)
				buf << "/" + part
			end
			uri_str = buf
		end

		if (config['uri_full_url'])
			url = self.ssl ? "https://" : "http://"
			url << self.config['vhost']
			url << ((self.port == 80) ? "" : ":#{self.port}")
			url << uri_str
			url
		else
			uri_str
		end
	end

	def set_cgi
		uri_str = uri.dup
		if (config['uri_dir_self_reference'])
			uri_str.gsub!('/', '/./')
		end

		if (config['uri_dir_fake_relative'])
			buf = ""
			uri_str.split('/').each do |part|
				cnt = rand(8)+2
				1.upto(cnt) { |idx|
					buf << "/" + Rex::Text.rand_text_alphanumeric(rand(32)+1)
				}
				buf << ("/.." * cnt)
				buf << "/" + part
			end
			uri_str = buf
		end

		url = uri_str

		if (config['uri_full_url'])
			url = self.ssl ? "https" : "http"
			url << self.config['vhost']
			url << (self.port == 80) ? "" : ":#{self.port}"
			url << uri_str
		end

		url
	end

	def set_encode_uri(str)
		a = str.dup
		config['uri_encode_count'].times {
			a = Rex::Text.uri_encode(a, config['uri_encode_mode'])
		}
		return a
	end

	def set_method
		ret = method.dup

		if (config['method_random_valid'])
			ret = ['GET', 'POST', 'HEAD'][rand(3)]
		end

		if (config['method_random_invalid'])
			ret = Rex::Text.rand_text_alpha(rand(20)+1)
		end

		if (config['method_random_case'])
			ret = Rex::Text.to_rand_case(ret)
		end

		ret
	end

	def set_method_uri_spacer
		len = config['pad_method_uri_count'].to_i
		set = " "
		buf = ""

		case config['pad_method_uri_type']
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

		if (config['uri_fake_params_start'])
			prefix << '/%3fa=b/../'
		end

		if (config['uri_fake_end'])
			prefix << '/%20HTTP/1.0/../../'
		end

		prefix
	end

	#
	# Return the HTTP path info
	# TODO:
	#  * Encode path information
	def set_path_info
		path ? path : ''
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
	# Return the spacing between the uri and the version
	#
	def set_uri_version_spacer
		len = config['pad_uri_version_count'].to_i
		set = " "
		buf = ""

		case config['pad_uri_version_type']
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
	# Return the HTTP version string
	#
	def set_version
		ret = protocol + "/" + version

		if (config['version_random_valid'])
			ret = protocol + "/" +  ['1.0', '1.1'][rand(2)]
		end

		if (config['version_random_invalid'])
			ret = Rex::Text.rand_text_alphanumeric(rand(20)+1)
		end

		if (config['version_random_case'])
			ret = Rex::Text.to_rand_case(ret)
		end

		ret << "\r\n"
	end

	#
	# Return the HTTP Host header
	#
	def set_host_header
		return "" if config['uri_full_url']
		host ||= config['vhost']

		# IPv6 addresses must be placed in brackets
		if Rex::Socket.is_ipv6?(host)
			host = "[#{host}]"
		end

		# The port should be appended if non-standard
		if not [80,443].include?(port)
			host = host + ":#{port}"
		end

		set_formatted_header("Host", host)
	end

	#
	# Return the HTTP agent header
	#
	def set_agent_header
		user_agent ? set_formatted_header("User-Agent", user_agent) : ""
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
	# Return the HTTP cookie header
	#
	def set_cookie_header
		cookie ? set_formatted_header("Cookie", cookie) : ""
	end

	#
	# Return the HTTP connection header
	#
	def set_connection_header
		connection ? set_formatted_header("Connection", connection) : ""
	end

	#
	# Return the content type header
	#
	def set_content_type_header
		set_formatted_header("Content-Type", content_type)
	end

	#
	# Return the content length header
	def set_content_len_header(clen)
		return "" if config['chunked_size'] > 0
		set_formatted_header("Content-Length", clen)
	end

	#
	# Return a string of formatted extra headers
	#
	def set_extra_headers
		buf = ''

		if (config['pad_fake_headers'])
			1.upto(config['pad_fake_headers_count'].to_i) do |i|
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

	def set_chunked_header
		return "" if config['chunked_size'] == 0
		set_formatted_header('Transfer-Encoding', 'chunked')
	end

	#
	# Return the HTTP seperator and body string
	#
	def set_body(bdata)
		return "\r\n" + bdata if config['chunked_size'] == 0
		str = bdata.dup
		chunked = ''
		while str.size > 0
			chunk = str.slice!(0,rand(config['chunked_size']) + 1)
			chunked << sprintf("%x", chunk.size) + "\r\n" + chunk + "\r\n"
		end
		"\r\n" + chunked + "0\r\n\r\n"
	end


end



end
end
end
