require 'rex/socket'
require 'rex/proto/http'

module Rex
module Proto
module Http

###
#
# ServerClient
# ------------
#
# Runtime extension of the HTTP clients that connect to the server.
#
###
module ServerClient

	#
	# Initialize a new request instance
	#
	def init_cli(server)
		self.request   = Request.new
		self.server    = server
		self.keepalive = false
	end

	#
	# Resets the parsing state
	#
	def reset_cli
		self.request.reset
	end

	#
	# Transmits a response and adds the appropriate headers
	#
	def send_response(response)
		# Set the connection to close or keep-alive depending on what the client
		# can support.
		response['Connection'] = (keepalive) ? 'Keep-Alive' : 'close'

		# Add any other standard response headers.
		server.add_response_headers(response)

		# Send it off.
		put(response.to_s)
	end

	#
	# The current request context
	#
	attr_accessor :request
	#
	# Boolean that indicates whether or not the connection supports keep-alive
	#
	attr_accessor :keepalive
	#
	# A reference to the server the client is associated with
	#
	attr_accessor :server

end

###
#
# Server
# ------
#
# Acts as an HTTP server, processing requests and dispatching them to
# registered procs.
#
###
class Server

	DefaultServer = "Rex"

	def initialize(port = 80, listen_host = '0.0.0.0')
		self.listen_port = port
		self.listen_host = listen_host
		self.listener    = nil
		self.clients     = []
		self.clifds      = []
		self.fd2cli      = {}
		self.resources   = {}
	end

	#
	# Listens on the defined port and host and starts monitoring for clients.
	#
	def start
		self.listener = Rex::Socket::TcpServer.create(
			'LocalHost' => self.listen_host,
			'LocalPort' => self.listen_port)

		self.listener_thread = Thread.new {
			monitor_listener
		}
		self.clients_thread = Thread.new {
			monitor_clients
		}
	end

	#
	# Terminates the monitor thread and turns off the listener.
	#
	def stop
		self.listener_thread.kill
		self.clients_thread.kill

		self.clients.each { |cli|
			close_client(cli)
		}

		self.listener.close
	end

	#
	# Closes the supplied client connection and removes it from the internal
	# hashes and lists.
	#
	def close_client(cli)
		if (cli)
			self.fd2cli.delete(cli.sock)
			self.clifds.delete(cli.sock)
			self.clients.delete(cli)
			cli.close
		end
	end

	#
	# Adds a resource handler, such as one for /, which will be called whenever
	# the resource is requested.  The ``opts'' parameter can have any of the
	# following:
	#
	# Proc     (proc) - The procedure to call when a request comes in for this resource.
	# LongCall (bool) - Hints to the server that this resource may have long
	#                   request processing times.
	#
	def add_resource(name, opts)
		if (self.resources[name])
			raise RuntimeError, 
				"The supplied resource '#{name}' is already added.", caller
		end

		self.resources[name] = opts
	end

	#
	# Removes the supplied resource handler.
	#
	def remove_resource(name)
		self.resources.delete(name)
	end

	#
	# Adds Server headers and stuff
	#
	def add_response_headers(resp)
		resp['Server'] = DefaultServer
	end

	attr_accessor :listen_port, :listen_host

protected

	attr_accessor :listener
	attr_accessor :listener_thread, :clients_thread
	attr_accessor :clients, :clifds, :fd2cli
	attr_accessor :resources

	#
	# Monitors the listener for new connections
	#
	def monitor_listener
		begin
			sd = Rex::ThreadSafe.select([ listener.sock ])

			# Accept the new client connection
			if (sd[0].length > 0)
				cli = listener.accept

				next if (!cli)

				cli.extend(ServerClient)

				# Initialize the server client extension
				cli.init_cli(self)

				# Insert it into some lists
				self.clients << cli
				self.clifds  << cli.sock
				self.fd2cli[cli.sock] = cli
			end
		rescue
			elog("Exception caught in HTTP server listener monitor: #{$!}")
		end while true
	end

	#
	# Monitors client connections for data
	#
	def monitor_clients
		begin
			if (clients.length == 0)
				Rex::ThreadSafe::sleep(0.2)
				next
			end

			sd = Rex::ThreadSafe.select(clifds)

			sd[0].each { |fd|
				process_client(self.fd2cli[fd])
			}
		rescue
			elog("Exception caught in HTTP server clients monitor: #{$!}")
		end while true
	end

	#
	# Processes data coming in from a client
	#
	def process_client(cli)
		begin
			case cli.request.parse(cli.get)
				when Packet::ParseCode::Completed
					dispatch_request(cli, cli.request)

					cli.reset_cli
				when Packet::ParseCode::Error
					close_client(cli)
			end
		rescue EOFError
			if (cli.request.completed?)
				dispatch_request(cli, cli.request)

				cli.reset_cli
			end

			close_client(cli)
		end
	end

	#
	# Dispatches the supplied request for a given connection
	#
	def dispatch_request(cli, request)
		# Is the client requesting keep-alive?
		if ((request['Connection']) and
		   (request['Connection'].downcase == 'Keep-Alive'.downcase))
			cli.keepalive = true
		end

		if (p = self.resources[request.resource])
			if (p['LongCall'] == true)
				Thread.new {
					p['Proc'].call(cli, request)
				}
			else
				p['Proc'].call(cli, request)
			end
		else
			send_e404(cli, request)
		end

		# If keep-alive isn't enabled for this client, close the connection
		if (cli.keepalive == false)
			close_client(cli)
		end
	end

	#
	# Sends a 404 error to the client for a given request.
	#
	def send_e404(cli, request)
		resp = Response::E404.new

		resp.body = 
			"<html><head>" +
			"<title>404 Not Found</title" +
			"</head><body>" +
			"<h1>Not found</h1>" +
			"The requested URL #{request.resource} was not found on this server.<p><hr>" +
			"</body></html>"

		# Send the response to the client like what
		cli.send_response(resp)
	end

end

end
end
end
