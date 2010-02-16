require 'net/ssh/loggable'

module Net; module SSH; module Service

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
    #   ssh.forward.local(1234, "www.capify.org", 80)
    #   ssh.forward.local("0.0.0.0", 1234, "www.capify.org", 80)
    def local(*args)
      if args.length < 3 || args.length > 4
        raise ArgumentError, "expected 3 or 4 parameters, got #{args.length}"
      end

      bind_address = "127.0.0.1"
      bind_address = args.shift if args.first.is_a?(String) && args.first =~ /\D/

      local_port = args.shift.to_i
      remote_host = args.shift
      remote_port = args.shift.to_i

      socket = TCPServer.new(bind_address, local_port)

      @local_forwarded_ports[[local_port, bind_address]] = socket

      session.listen_to(socket) do |server|
        client = server.accept
        debug { "received connection on #{bind_address}:#{local_port}" }

        channel = session.open_channel("direct-tcpip", :string, remote_host, :long, remote_port, :string, bind_address, :long, local_port) do |achannel|
          achannel.info { "direct channel established" }
        end

        prepare_client(client, channel, :local)
  
        channel.on_open_failed do |ch, code, description|
          channel.error { "could not establish direct channel: #{description} (#{code})" }
          channel[:socket].close
        end
      end
    end

    # Terminates an active local forwarded port. If no such forwarded port
    # exists, this will raise an exception. Otherwise, the forwarded connection
    # is terminated.
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

    # Requests that all connections on the given remote-port be forwarded via
    # the local host to the given port/host. The last argument describes the
    # bind address on the remote host, and defaults to 127.0.0.1.
    #
    # This method will return immediately, but the port will not actually be
    # forwarded immediately. If the remote server is not able to begin the
    # listener for this request, an exception will be raised asynchronously.
    #
    # If you want to know when the connection is active, it will show up in the
    # #active_remotes list. If you want to block until the port is active, you
    # could do something like this:
    #
    #   ssh.forward.remote(80, "www.google.com", 1234, "0.0.0.0")
    #   ssh.loop { !ssh.forward.active_remotes.include?([1234, "0.0.0.0"]) }
    def remote(port, host, remote_port, remote_host="127.0.0.1")
      session.send_global_request("tcpip-forward", :string, remote_host, :long, remote_port) do |success, response|
        if success
          debug { "remote forward from remote #{remote_host}:#{remote_port} to #{host}:#{port} established" }
          @remote_forwarded_ports[[remote_port, remote_host]] = Remote.new(host, port)
        else
          error { "remote forwarding request failed" }
          raise Net::SSH::Exception, "remote forwarding request failed"
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

    # Enables SSH agent forwarding on the given channel. The forwarded agent
    # will remain active even after the channel closes--the channel is only
    # used as the transport for enabling the forwarded connection. You should
    # never need to call this directly--it is called automatically the first
    # time a session channel is opened, when the connection was created with
    # :forward_agent set to true:
    #
    #    Net::SSH.start("remote.host", "me", :forwrd_agent => true) do |ssh|
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
        client.logger = logger

        session.listen_to(client)
        channel[:socket] = client

        channel.on_data do |ch, data|
          ch[:socket].enqueue(data)
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
          agent = Authentication::Agent.connect(logger)
          prepare_client(agent.socket, channel, :agent)
        rescue Exception => e
          error { "attempted to connect to agent but failed: #{e.class.name} (#{e.message})" }
          raise Net::SSH::ChannelOpenFailed.new(2, "could not connect to authentication agent")
        end
      end
  end

end; end; end