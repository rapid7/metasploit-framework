require 'net/ssh/loggable'

module Net
  module SSH
    module Service

      # This class implements various port forwarding services for use by
      # Net::SSH clients. The Forward class should never need to be instantiated
      # directly; instead, it should be accessed via the singleton instance
      # returned by Connection::Session#forward:
      #
      #   ssh.forward.local(1234, "www.capify.org", 80)
      class Forward
        include Loggable

        # The underlying connection service instance that the port-forwarding
        # services employ.
        attr_reader :session

        # A simple class for representing a requested remote forwarded port.
        Remote = Struct.new(:host, :port) #:nodoc:

        # Instantiates a new Forward service instance atop the given connection
        # service session. This will register new channel open handlers to handle
        # the specialized channels that the SSH port forwarding protocols employ.
        def initialize(session)
          @session = session
          self.logger = session.logger
          @remote_forwarded_ports = {}
          @local_forwarded_ports = {}
          @agent_forwarded = false
          @local_forwarded_sockets = {}

          session.on_open_channel('forwarded-tcpip', &method(:forwarded_tcpip))
          session.on_open_channel('auth-agent', &method(:auth_agent_channel))
          session.on_open_channel('auth-agent@openssh.com', &method(:auth_agent_channel))
        end

        # Starts listening for connections on the local host, and forwards them
        # to the specified remote host/port via the SSH connection. This method
        # accepts either three or four arguments. When four arguments are given,
        # they are:
        #
        # * the local address to bind to
        # * the local port to listen on
        # * the remote host to forward connections to
        # * the port on the remote host to connect to
        #
        # If three arguments are given, it is as if the local bind address is
        # "127.0.0.1", and the rest are applied as above.
        #
        # To request an ephemeral port on the remote server, provide 0 (zero) for
        # the port number. In all cases, this method will return the port that
        # has been assigned.
        #
        #   ssh.forward.local(1234, "www.capify.org", 80)
        #   assigned_port = ssh.forward.local("0.0.0.0", 0, "www.capify.org", 80)
        def local(*args)
          if args.length < 3 || args.length > 4
            raise ArgumentError, "expected 3 or 4 parameters, got #{args.length}"
          end

          local_port_type = :long

          socket = begin
            if defined?(UNIXServer) and args.first.class == UNIXServer
              local_port_type = :string
              args.shift
            else
              bind_address = "127.0.0.1"
              bind_address = args.shift if args.first.is_a?(String) && args.first =~ /\D/
              local_port = args.shift.to_i
              local_port_type = :long
              TCPServer.new(bind_address, local_port)
            end
          end

          local_port = socket.addr[1] if local_port == 0 # ephemeral port was requested
          remote_host = args.shift
          remote_port = args.shift.to_i

          @local_forwarded_ports[[local_port, bind_address]] = socket

          session.listen_to(socket) do |server|
            client = server.accept
            debug { "received connection on #{socket}" }

            channel = session.open_channel("direct-tcpip", :string, remote_host, :long, remote_port, :string, bind_address, local_port_type, local_port) do |achannel|
              achannel.info { "direct channel established" }
            end

            prepare_client(client, channel, :local)

            channel.on_open_failed do |ch, code, description|
              channel.error { "could not establish direct channel: #{description} (#{code})" }
              session.stop_listening_to(channel[:socket])
              channel[:socket].close
            end
          end

          local_port
        end

        # Terminates an active local forwarded port.
        #
        #   ssh.forward.cancel_local(1234)
        #   ssh.forward.cancel_local(1234, "0.0.0.0")
        def cancel_local(port, bind_address="127.0.0.1")
          socket = @local_forwarded_ports.delete([port, bind_address])
          socket.shutdown rescue nil
          socket.close rescue nil
          session.stop_listening_to(socket)
        end

        # Returns a list of all active locally forwarded ports. The returned value
        # is an array of arrays, where each element is a two-element tuple
        # consisting of the local port and bind address corresponding to the
        # forwarding port.
        def active_locals
          @local_forwarded_ports.keys
        end

        # Starts listening for connections on the local host, and forwards them
        # to the specified remote socket via the SSH connection. This will
        # (re)create the local socket file. The remote server needs to have the
        # socket file already available.
        #
        #   ssh.forward.local_socket('/tmp/local.sock', '/tmp/remote.sock')
        def local_socket(local_socket_path, remote_socket_path)
          File.delete(local_socket_path) if File.exist?(local_socket_path)
          socket = Socket.unix_server_socket(local_socket_path)

          @local_forwarded_sockets[local_socket_path] = socket

          session.listen_to(socket) do |server|
            client = server.accept[0]
            debug { "received connection on #{socket}" }

            channel = session.open_channel("direct-streamlocal@openssh.com",
                                           :string, remote_socket_path,
                                           :string, nil,
                                           :long, 0) do |achannel|
              achannel.info { "direct channel established" }
            end

            prepare_client(client, channel, :local)

            channel.on_open_failed do |ch, code, description|
              channel.error { "could not establish direct channel: #{description} (#{code})" }
              session.stop_listening_to(channel[:socket])
              channel[:socket].close
            end
          end

          local_socket_path
        end

        # Terminates an active local forwarded socket.
        #
        #   ssh.forward.cancel_local_socket('/tmp/foo.sock')
        def cancel_local_socket(local_socket_path)
          socket = @local_forwarded_sockets.delete(local_socket_path)
          socket.shutdown rescue nil
          socket.close rescue nil
          session.stop_listening_to(socket)
        end

        # Returns a list of all active locally forwarded sockets. The returned value
        # is an array of Unix domain socket file paths.
        def active_local_sockets
          @local_forwarded_sockets.keys
        end

        # Requests that all connections on the given remote-port be forwarded via
        # the local host to the given port/host. The last argument describes the
        # bind address on the remote host, and defaults to 127.0.0.1.
        #
        # This method will return immediately, but the port will not actually be
        # forwarded immediately. If the remote server is not able to begin the
        # listener for this request, an exception will be raised asynchronously.
        #
        # To request an ephemeral port on the remote server, provide 0 (zero) for
        # the port number. The assigned port will show up in the # #active_remotes
        # list.
        #
        # remote_host is interpreted by the server per RFC 4254, which has these
        # special values:
        #
        # - "" means that connections are to be accepted on all protocol
        #   families supported by the SSH implementation.
        # - "0.0.0.0" means to listen on all IPv4 addresses.
        # - "::" means to listen on all IPv6 addresses.
        # - "localhost" means to listen on all protocol families supported by
        #   the SSH implementation on loopback addresses only ([RFC3330] and
        #   [RFC3513]).
        # - "127.0.0.1" and "::1" indicate listening on the loopback
        #   interfaces for IPv4 and IPv6, respectively.
        #
        # You may pass a block that will be called when the the port forward
        # request receives a response.  This block will be passed the remote_port
        # that was actually bound to, or nil if the binding failed.  If the block
        # returns :no_exception, the "failed binding" exception will not be thrown.
        #
        # If you want to block until the port is active, you could do something
        # like this:
        #
        #   got_remote_port = nil
        #   remote(port, host, remote_port, remote_host) do |actual_remote_port|
        #     got_remote_port = actual_remote_port || :error
        #     :no_exception # will yield the exception on my own thread
        #   end
        #   session.loop { !got_remote_port }
        #   if got_remote_port == :error
        #     raise Net::SSH::Exception, "remote forwarding request failed"
        #   end
        #
        def remote(port, host, remote_port, remote_host="127.0.0.1")
          session.send_global_request("tcpip-forward", :string, remote_host, :long, remote_port) do |success, response|
            if success
              remote_port = response.read_long if remote_port == 0
              debug { "remote forward from remote #{remote_host}:#{remote_port} to #{host}:#{port} established" }
              @remote_forwarded_ports[[remote_port, remote_host]] = Remote.new(host, port)
              yield remote_port, remote_host if block_given?
            else
              instruction = if block_given?
                              yield :error
                            end
              unless instruction == :no_exception
                error { "remote forwarding request failed" }
                raise Net::SSH::Exception, "remote forwarding request failed"
              end
            end
          end
        end

        # an alias, for token backwards compatibility with the 1.x API
        alias :remote_to :remote

        # Requests that a remote forwarded port be cancelled. The remote forwarded
        # port on the remote host, bound to the given address on the remote host,
        # will be terminated, but not immediately. This method returns immediately
        # after queueing the request to be sent to the server. If for some reason
        # the port cannot be cancelled, an exception will be raised (asynchronously).
        #
        # If you want to know when the connection has been cancelled, it will no
        # longer be present in the #active_remotes list. If you want to block until
        # the port is no longer active, you could do something like this:
        #
        #   ssh.forward.cancel_remote(1234, "0.0.0.0")
        #   ssh.loop { ssh.forward.active_remotes.include?([1234, "0.0.0.0"]) }
        def cancel_remote(port, host="127.0.0.1")
          session.send_global_request("cancel-tcpip-forward", :string, host, :long, port) do |success, response|
            if success
              @remote_forwarded_ports.delete([port, host])
            else
              raise Net::SSH::Exception, "could not cancel remote forward request on #{host}:#{port}"
            end
          end
        end

        # Returns all active forwarded remote ports. The returned value is an
        # array of two-element tuples, where the first element is the port on the
        # remote host and the second is the bind address.
        def active_remotes
          @remote_forwarded_ports.keys
        end

        # Returns all active remote forwarded ports and where they forward to. The
        # returned value is a hash from [<forwarding port on the local host>, <local forwarding address>]
        # to [<port on the remote host>, <remote bind address>].
        def active_remote_destinations
          @remote_forwarded_ports.each_with_object({}) do |(remote, local), result|
            result[[local.port, local.host]] = remote
          end
        end

        # Enables SSH agent forwarding on the given channel. The forwarded agent
        # will remain active even after the channel closes--the channel is only
        # used as the transport for enabling the forwarded connection. You should
        # never need to call this directly--it is called automatically the first
        # time a session channel is opened, when the connection was created with
        # :forward_agent set to true:
        #
        #    Net::SSH.start("remote.host", "me", :forward_agent => true) do |ssh|
        #      ssh.open_channel do |ch|
        #        # agent will be automatically forwarded by this point
        #      end
        #      ssh.loop
        #    end
        def agent(channel)
          return if @agent_forwarded
          @agent_forwarded = true

          channel.send_channel_request("auth-agent-req@openssh.com") do |achannel, success|
            if success
              debug { "authentication agent forwarding is active" }
            else
              achannel.send_channel_request("auth-agent-req") do |a2channel, success2|
                if success2
                  debug { "authentication agent forwarding is active" }
                else
                  error { "could not establish forwarding of authentication agent" }
                end
              end
            end
          end
        end

        private

        # Perform setup operations that are common to all forwarded channels.
        # +client+ is a socket, +channel+ is the channel that was just created,
        # and +type+ is an arbitrary string describing the type of the channel.
        def prepare_client(client, channel, type)
          client.extend(Net::SSH::BufferedIo)
          client.extend(Net::SSH::ForwardedBufferedIo)
          client.logger = logger

          session.listen_to(client)
          channel[:socket] = client

          channel.on_data do |ch, data|
            debug { "data:#{data.length} on #{type} forwarded channel" }
            ch[:socket].enqueue(data)
          end

          channel.on_eof do |ch|
            debug { "eof #{type} on #{type} forwarded channel" }
            begin
              ch[:socket].send_pending
              ch[:socket].shutdown Socket::SHUT_WR
            rescue IOError => e
              if e.message =~ /closed/ then
                debug { "epipe in on_eof => shallowing exception:#{e}" }
              else
                raise
              end
            rescue Errno::EPIPE => e
              debug { "epipe in on_eof => shallowing exception:#{e}" }
            rescue Errno::ENOTCONN => e
              debug { "enotconn in on_eof => shallowing exception:#{e}" }
            end
          end

          channel.on_close do |ch|
            debug { "closing #{type} forwarded channel" }
            ch[:socket].close if !client.closed?
            session.stop_listening_to(ch[:socket])
          end

          channel.on_process do |ch|
            if ch[:socket].closed?
              ch.info { "#{type} forwarded connection closed" }
              ch.close
            elsif ch[:socket].available > 0
              data = ch[:socket].read_available(8192)
              ch.debug { "read #{data.length} bytes from client, sending over #{type} forwarded connection" }
              ch.send_data(data)
            end
          end
        end

        # not a real socket, so use a simpler behaviour
        def prepare_simple_client(client, channel, type)
          channel[:socket] = client

          channel.on_data do |ch, data|
            ch.debug { "data:#{data.length} on #{type} forwarded channel" }
            ch[:socket].send(data)
          end

          channel.on_process do |ch|
            data = ch[:socket].read(8192)
            if data
              ch.debug { "read #{data.length} bytes from client, sending over #{type} forwarded connection" }
              ch.send_data(data)
            end
          end
        end

        # The callback used when a new "forwarded-tcpip" channel is requested
        # by the server.  This will open a new socket to the host/port specified
        # when the forwarded connection was first requested.
        def forwarded_tcpip(session, channel, packet)
          connected_address  = packet.read_string
          connected_port     = packet.read_long
          originator_address = packet.read_string
          originator_port    = packet.read_long

          remote = @remote_forwarded_ports[[connected_port, connected_address]]

          if remote.nil?
            raise Net::SSH::ChannelOpenFailed.new(1, "unknown request from remote forwarded connection on #{connected_address}:#{connected_port}")
          end

          client = TCPSocket.new(remote.host, remote.port)
          info { "connected #{connected_address}:#{connected_port} originator #{originator_address}:#{originator_port}" }

          prepare_client(client, channel, :remote)
        rescue SocketError => err
          raise Net::SSH::ChannelOpenFailed.new(2, "could not connect to remote host (#{remote.host}:#{remote.port}): #{err.message}")
        end

        # The callback used when an auth-agent channel is requested by the server.
        def auth_agent_channel(session, channel, packet)
          info { "opening auth-agent channel" }
          channel[:invisible] = true

          begin
            agent = Authentication::Agent.connect(logger, session.options[:agent_socket_factory])
            if (agent.socket.is_a? ::IO)
              prepare_client(agent.socket, channel, :agent)
            else
              prepare_simple_client(agent.socket, channel, :agent)
            end
          rescue Exception => e
            error { "attempted to connect to agent but failed: #{e.class.name} (#{e.message})" }
            raise Net::SSH::ChannelOpenFailed.new(2, "could not connect to authentication agent")
          end
        end
      end

    end
  end
end
