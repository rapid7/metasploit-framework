require 'rex/socket'
require 'rex/proto/http'

module Rex
module Proto
module Http

###
#
# Acts as a client to an HTTP server, sending requests and receiving
# responses.  This is modeled somewhat after Net::HTTP.
#
###
class Client

	include Proto

	#
	# Performs a block-based HTTP operation.
	#
	def self.start(host, &block)
		c = Client.new(host)

		begin
			block.call(c)
		ensure
			c.stop
		end
	end
	
	#
	# Initializes a GET request and returns it to the caller.
	#
	def gen_get(uri = '/', proto = DefaultProtocol)
		return init_request(Request::Get.new(uri, proto))
	end

	#
	# Initializes a POST request and returns it to the caller.
	#
	def gen_post(uri = '/', proto = DefaultProtocol)
		return init_request(Request::Post.new(uri, proto))
	end

	def initialize(host, port = 80)
		self.hostname = host
		self.port     = port.to_i
		self.request_config = {}
		self.client_config  = {}
	end

	#
	# HTTP client.
	#
	def alias
		"HTTP Client"
	end

	#
	# Configures the Client object and the Request factory.
	#
	def config (chash)
		req_opts = %w{ user-agent vhost cookie proto }
		cli_opts = %w{ max-data }	
		chash.each_pair { |k,v| 
			req_opts.include?(k) ? 
				self.request_config[k] = v : self.client_config[k] = v 
		}
	end

	#
	# Set parameters for the Request factory.
	#
	def request_option(k, v)
		(v != nil) ? self.request_config[k] = v : self.request_config[k]
	end
	
	#
	# Set parameters for the actual Client.
	#
	def client_option(k, v)
		(v != nil) ? self.client_config[k] = v : self.client_config[k]
	end
	
	#
	# The Request factory.
	#
	def request (chash) 
		method = chash['method']
		proto  = chash['proto']  || self.request_config['proto']
		uri    = chash['uri'] 
		
		req    = Rex::Proto::Http::Request.new(method, uri, proto)
		
		#
		# Configure the request headers using the Client configuration
		#

		if self.request_config['cookie']
			req['Cookie'] = self.request_config['cookie']
		end
		
		if self.request_config['user-agent']
			req['User-Agent'] = self.request_config['user-agent']
		end
		
		#
		# Configure the rest of the request based on config hash
		#		
		req['Host'] = (self.request_config['vhost'] || self.hostname) + ':' + self.port.to_s
		
		# Set the request body if a data chunk has been specified
		if chash['data']
			req.body = chash['data']
		end
		
		# Set the content-type
		if chash['content-type']
			req['Content-Type'] = chash['content-type']
		end

		req
	end
	
	#
	# Connects to the remote server if possible.
	#
	def connect
		# If we already have a connection and we aren't pipelining, close it.
		if (self.conn and !pipelining?)
			close
		end

		self.conn = Rex::Socket::Tcp.create(
			'PeerHost'  => self.hostname,
			'PeerPort'  => self.port.to_i,
			'LocalHost' => self.local_host,
			'LocalPort' => self.local_port)
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
	# Initializes a request by setting the host header and other cool things.
	#
	def init_request(req)
		req['Host'] = "#{request_config.has_key?('vhost') ? request_config['vhost'] : hostname}:#{port}"

		return req
	end

	#
	# Transmits a request and reads in a response.
	#
	def send_request(req, t = -1)
		resp = Response.new
		resp.max_data = self.client_config['max-data']
		
		# Connect to the server
		connect

		# Send it on over
		conn.put(req.to_s)

		# Tell the remote side if we aren't pipelining
		conn.shutdown(::Socket::SHUT_WR) if (!pipelining?)

		# Wait at most t seconds for the full response to be read in.  We only
		# do this if t was specified as a negative value indicating an infinite
		# wait cycle.  If t were specified as nil it would indicate that no
		# response parsing is required.
		timeout((t < 0) ? nil : t) {
			# Now, read in the response until we're good to go.
			begin
				# Keep running until we finish parsing or EOF is reached
				while ((rv = resp.parse(conn.get)) != Packet::ParseCode::Completed)
					# Parsing error?  Raise an exception, our job is done.
					if (rv == Packet::ParseCode::Error)
						raise RuntimeError, resp.error, caller
					end
				end
			rescue EOFError
			end
		} if (t)

		# Close our side if we aren't pipelining
		close if (!pipelining?)

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
	# Client configuration attributes.
	#
	attr_accessor :client_config
	#
	# The underlying connection.
	#
	attr_accessor :conn
	
protected

	attr_accessor :hostname, :port # :nodoc:
	attr_accessor :request_config, :client_config # :nodoc:
	
end

end
end
end
