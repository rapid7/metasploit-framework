require 'rex/socket'
require 'rex/proto/http'

module Rex
module Proto
module Http

###
#
# Client
# ------
#
# Acts as a client to an HTTP server, sending requests and receiving
# responses.  This is modeled somewhat after Net::HTTP.
#
###
class Client

	#
	# Performs a block-based HTTP operation
	#
	def self.start(host, &block)
		c = Client.new(host)

		begin
			block.call(c)
		ensure
			c.stop
		end
	end

	def self.get(uri = '/', proto = DefaultProtocol)
		return init_request(Request::Get.new(uri, proto))
	end

	def initialize(host, port = 80)
		self.hostname = host
		self.port     = port.to_i
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
		self.conn.close if (self.conn)
		self.conn = nil
	end

	#
	# Initializes a request by setting the host header and other cool things.
	#
	def init_request(req)
		req['Host'] = "#{hostname}:#{port}"

		return req
	end

	#
	# Transmits a request and reads in a response
	#
	def send_request(req, t = -1)
		resp = Response.new

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

		# Returns the response to the caller
		return (resp.completed?) ? resp : nil
	end

	#
	# Cleans up any outstanding connections and other resources
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
	# Whether or not connections should be pipelined
	#
	def pipelining?
		pipeline
	end

	attr_accessor :pipeline
	attr_accessor :local_host
	attr_accessor :local_port

protected

	attr_accessor :hostname, :port
	attr_accessor :conn

end

end
end
end
