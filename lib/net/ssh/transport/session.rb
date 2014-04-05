# -*- coding: binary -*-
require 'rex/socket'
require 'timeout'

require 'net/ssh/errors'
require 'net/ssh/loggable'
require 'net/ssh/version'
require 'net/ssh/transport/algorithms'
require 'net/ssh/transport/constants'
require 'net/ssh/transport/packet_stream'
require 'net/ssh/transport/server_version'
require 'net/ssh/verifiers/null'
require 'net/ssh/verifiers/strict'
require 'net/ssh/verifiers/lenient'

module Net; module SSH; module Transport

  # The transport layer represents the lowest level of the SSH protocol, and
  # implements basic message exchanging and protocol initialization. It will
  # never be instantiated directly (unless you really know what you're about),
  # but will instead be created for you automatically when you create a new
  # SSH session via Net::SSH.start.
  class Session
    include Constants, Loggable

    # The standard port for the SSH protocol.
    DEFAULT_PORT = 22

    # The host to connect to, as given to the constructor.
    attr_reader :host

    # The port number to connect to, as given in the options to the constructor.
    # If no port number was given, this will default to DEFAULT_PORT.
    attr_reader :port

    # The underlying socket object being used to communicate with the remote
    # host.
    attr_reader :socket

    # The ServerVersion instance that encapsulates the negotiated protocol
    # version.
    attr_reader :server_version

    # Internal compatibility flags (hacks/tweaks/etc)
    attr_reader :compat_flags

    # The Algorithms instance used to perform key exchanges.
    attr_reader :algorithms

    # The host-key verifier object used to verify host keys, to ensure that
    # the connection is not being spoofed.
    attr_reader :host_key_verifier

    # The hash of options that were given to the object at initialization.
    attr_reader :options

    # Instantiates a new transport layer abstraction. This will block until
    # the initial key exchange completes, leaving you with a ready-to-use
    # transport session.
    def initialize(host, options={})
      self.logger = options[:logger]

      @host = host
      @port = options[:port] || DEFAULT_PORT
      @options = options

      debug { "establishing connection to #{@host}:#{@port}" }
      factory = options[:proxy]

      if (factory)
        @socket = timeout(options[:timeout] || 0) { factory.open(@host, @port) }
      else
        @socket = timeout(options[:timeout] || 0) {
          Rex::Socket::Tcp.create(
          	'PeerHost' => @host,
          	'PeerPort' => @port,
            'Proxies' => options[:proxies],
          	'Context'  => {
          	  'Msf'          => options[:msframework],
          	  'MsfExploit'   => options[:msfmodule]
            }
          )
        }
        # Tell MSF to automatically close this socket on error or completion...
      # This prevents resource leaks.
      options[:msfmodule].add_socket(@socket) if options[:msfmodule]
      end

      @socket.extend(PacketStream)
      @socket.logger = @logger

      debug { "connection established" }

      @queue = []

      @host_key_verifier = select_host_key_verifier(options[:paranoid])

      @server_version = ServerVersion.new(socket, logger)

      # Compatibility settings
      ver = @server_version.version
      @compat_flags = 0
      if ver =~ /OpenSSH_2\.[0-3]/ or ver =~ /OpenSSH_2\.5\.[0-2]/
        @compat_flags |= COMPAT_OLD_DHGEX
      end

      @algorithms = Algorithms.new(self, options)
      wait { algorithms.initialized? }
    end

    # Returns the host (and possibly IP address) in a format compatible with
    # SSH known-host files.
    def host_as_string
      @host_as_string ||= begin
        string = "#{host}"
        string = "[#{string}]:#{port}" if port != DEFAULT_PORT
        if socket.peer_ip != host
          string2 = socket.peer_ip
          string2 = "[#{string2}]:#{port}" if port != DEFAULT_PORT
          string << "," << string2
        end
        string
      end
    end

    # Returns true if the underlying socket has been closed.
    def closed?
      socket.closed?
    end

    # Cleans up (see PacketStream#cleanup) and closes the underlying socket.
    def close
      socket.cleanup
      socket.close
    end

    # Performs a "hard" shutdown of the connection. In general, this should
    # never be done, but it might be necessary (in a rescue clause, for instance,
    # when the connection needs to close but you don't know the status of the
    # underlying protocol's state).
    def shutdown!
      error { "forcing connection closed" }
      socket.close
    end

    # Returns a new service_request packet for the given service name, ready
    # for sending to the server.
    def service_request(service)
      Net::SSH::Buffer.from(:byte, SERVICE_REQUEST, :string, service)
    end

    # Requests a rekey operation, and blocks until the operation completes.
    # If a rekey is already pending, this returns immediately, having no
    # effect.
    def rekey!
      if !algorithms.pending?
        algorithms.rekey!
        wait { algorithms.initialized? }
      end
    end

    # Returns immediately if a rekey is already in process. Otherwise, if a
    # rekey is needed (as indicated by the socket, see PacketStream#if_needs_rekey?)
    # one is performed, causing this method to block until it completes.
    def rekey_as_needed
      return if algorithms.pending?
      socket.if_needs_rekey? { rekey! }
    end

    # Returns a hash of information about the peer (remote) side of the socket,
    # including :ip, :port, :host, and :canonized (see #host_as_string).
    def peer
      @peer ||= { :ip => socket.peer_ip, :port => @port.to_i, :host => @host, :canonized => host_as_string }
    end

    # Blocks until a new packet is available to be read, and returns that
    # packet. See #poll_message.
    def next_message
      poll_message(:block)
    end

    # Tries to read the next packet from the socket. If mode is :nonblock (the
    # default), this will not block and will return nil if there are no packets
    # waiting to be read. Otherwise, this will block until a packet is
    # available. Note that some packet types (DISCONNECT, IGNORE, UNIMPLEMENTED,
    # DEBUG, and KEXINIT) are handled silently by this method, and will never
    # be returned.
    #
    # If a key-exchange is in process and a disallowed packet type is
    # received, it will be enqueued and otherwise ignored. When a key-exchange
    # is not in process, and consume_queue is true, packets will be first
    # read from the queue before the socket is queried.
    def poll_message(mode=:nonblock, consume_queue=true)
      loop do
        if consume_queue && @queue.any? && algorithms.allow?(@queue.first)
          return @queue.shift
        end

        packet = socket.next_packet(mode)
        return nil if packet.nil?

        case packet.type
        when DISCONNECT
          raise Net::SSH::Disconnect, "disconnected: #{packet[:description]} (#{packet[:reason_code]})"

        when IGNORE
          debug { "IGNORE packet recieved: #{packet[:data].inspect}" }

        when UNIMPLEMENTED
          lwarn { "UNIMPLEMENTED: #{packet[:number]}" }

        when DEBUG
          send(packet[:always_display] ? :fatal : :debug) { packet[:message] }

        when KEXINIT
          algorithms.accept_kexinit(packet)

        else
          return packet if algorithms.allow?(packet)
          push(packet)
        end
      end
    end

    # Waits (blocks) until the given block returns true. If no block is given,
    # this just waits long enough to see if there are any pending packets. Any
    # packets read are enqueued (see #push).
    def wait
      loop do
        break if block_given? && yield
        message = poll_message(:nonblock, false)
        push(message) if message
        break if !block_given?
      end
    end

    # Adds the given packet to the packet queue. If the queue is non-empty,
    # #poll_message will return packets from the queue in the order they
    # were received.
    def push(packet)
      @queue.push(packet)
    end

    # Sends the given message via the packet stream, blocking until the
    # entire message has been sent.
    def send_message(message)
      socket.send_packet(message)
    end

    # Enqueues the given message, such that it will be sent at the earliest
    # opportunity. This does not block, but returns immediately.
    def enqueue_message(message)
      socket.enqueue_packet(message)
    end

    # Configure's the packet stream's client state with the given set of
    # options. This is typically used to define the cipher, compression, and
    # hmac algorithms to use when sending packets to the server.
    def configure_client(options={})
      socket.client.set(options)
    end

    # Configure's the packet stream's server state with the given set of
    # options. This is typically used to define the cipher, compression, and
    # hmac algorithms to use when reading packets from the server.
    def configure_server(options={})
      socket.server.set(options)
    end

    # Sets a new hint for the packet stream, which the packet stream may use
    # to change its behavior. (See PacketStream#hints).
    def hint(which, value=true)
      socket.hints[which] = value
    end

    public

      # this method is primarily for use in tests
      attr_reader :queue #:nodoc:

    private

      # Instantiates a new host-key verification class, based on the value of
      # the parameter. When true or nil, the default Lenient verifier is
      # returned. If it is false, the Null verifier is returned, and if it is
      # :very, the Strict verifier is returned. If the argument happens to
      # respond to :verify, it is returned directly. Otherwise, an exception
      # is raised.
      def select_host_key_verifier(paranoid)
        case paranoid
        when true, nil then
          Net::SSH::Verifiers::Lenient.new
        when false then
          Net::SSH::Verifiers::Null.new
        when :very then
          Net::SSH::Verifiers::Strict.new
        else
          if paranoid.respond_to?(:verify)
            paranoid
          else
            raise ArgumentError, "argument to :paranoid is not valid: #{paranoid.inspect}"
          end
        end
      end
  end
end; end; end

