module EventMachine
  class FileNotFoundException < Exception
  end

  # EventMachine::Connection is a class that is instantiated
  # by EventMachine's processing loop whenever a new connection
  # is created. (New connections can be either initiated locally
  # to a remote server or accepted locally from a remote client.)
  # When a Connection object is instantiated, it <i>mixes in</i>
  # the functionality contained in the user-defined module
  # specified in calls to {EventMachine.connect} or {EventMachine.start_server}.
  # User-defined handler modules may redefine any or all of the standard
  # methods defined here, as well as add arbitrary additional code
  # that will also be mixed in.
  #
  # EventMachine manages one object inherited from EventMachine::Connection
  # (and containing the mixed-in user code) for every network connection
  # that is active at any given time.
  # The event loop will automatically call methods on EventMachine::Connection
  # objects whenever specific events occur on the corresponding connections,
  # as described below.
  #
  # This class is never instantiated by user code, and does not publish an
  # initialize method. The instance methods of EventMachine::Connection
  # which may be called by the event loop are:
  #
  # * {#post_init}
  # * {#connection_completed}
  # * {#receive_data}
  # * {#unbind}
  # * {#ssl_verify_peer} (if TLS is used)
  # * {#ssl_handshake_completed}
  #
  # All of the other instance methods defined here are called  only by user code.
  #
  # @see file:docs/GettingStarted.md EventMachine tutorial
  class Connection
    # @private
    attr_accessor :signature

    # @private
    alias original_method method

    # Override .new so subclasses don't have to call super and can ignore
    # connection-specific arguments
    #
    # @private
    def self.new(sig, *args)
      allocate.instance_eval do
        # Store signature
        @signature = sig
        # associate_callback_target sig

        # Call a superclass's #initialize if it has one
        initialize(*args)

        # post initialize callback
        post_init

        self
      end
    end

    # Stubbed initialize so legacy superclasses can safely call super
    #
    # @private
    def initialize(*args)
    end

    # Called by the event loop immediately after the network connection has been established,
    # and before resumption of the network loop.
    # This method is generally not called by user code, but is called automatically
    # by the event loop. The base-class implementation is a no-op.
    # This is a very good place to initialize instance variables that will
    # be used throughout the lifetime of the network connection.
    #
    # @see #connection_completed
    # @see #unbind
    # @see #send_data
    # @see #receive_data
    def post_init
    end

    # Called by the event loop whenever data has been received by the network connection.
    # It is never called by user code. {#receive_data} is called with a single parameter, a String containing
    # the network protocol data, which may of course be binary. You will
    # generally redefine this method to perform your own processing of the incoming data.
    #
    # Here's a key point which is essential to understanding the event-driven
    # programming model: <i>EventMachine knows absolutely nothing about the protocol
    # which your code implements.</i> You must not make any assumptions about
    # the size of the incoming data packets, or about their alignment on any
    # particular intra-message or PDU boundaries (such as line breaks).
    # receive_data can and will send you arbitrary chunks of data, with the
    # only guarantee being that the data is presented to your code in the order
    # it was collected from the network. Don't even assume that the chunks of
    # data will correspond to network packets, as EventMachine can and will coalesce
    # several incoming packets into one, to improve performance. The implication for your
    # code is that you generally will need to implement some kind of a state machine
    # in your redefined implementation of receive_data. For a better understanding
    # of this, read through the examples of specific protocol handlers in EventMachine::Protocols
    #
    # The base-class implementation (which will be invoked only if you didn't override it in your protocol handler)
    # simply prints incoming data packet size to stdout.
    #
    # @param [String] data Opaque incoming data.
    # @note Depending on the protocol, buffer sizes and OS networking stack configuration, incoming data may or may not be "a complete message".
    #       It is up to this handler to detect content boundaries to determine whether all the content (for example, full HTTP request)
    #       has been received and can be processed.
    #
    # @see #post_init
    # @see #connection_completed
    # @see #unbind
    # @see #send_data
    # @see file:docs/GettingStarted.md EventMachine tutorial
    def receive_data data
      puts "............>>>#{data.length}"
    end

    # Called by EventMachine when the SSL/TLS handshake has
    # been completed, as a result of calling #start_tls to initiate SSL/TLS on the connection.
    #
    # This callback exists because {#post_init} and {#connection_completed} are **not** reliable
    # for indicating when an SSL/TLS connection is ready to have its certificate queried for.
    #
    # @see #get_peer_cert
    def ssl_handshake_completed
    end

    # Called by EventMachine when :verify_peer => true has been passed to {#start_tls}.
    # It will be called with each certificate in the certificate chain provided by the remote peer.
    #
    # The cert will be passed as a String in PEM format, the same as in {#get_peer_cert}. It is up to user defined
    # code to perform a check on the certificates. The return value from this callback is used to accept or deny the peer.
    # A return value that is not nil or false triggers acceptance. If the peer is not accepted, the connection
    # will be subsequently closed.
    #
    # @example This server always accepts all peers
    #
    #   module AcceptServer
    #     def post_init
    #       start_tls(:verify_peer => true)
    #     end
    #
    #     def ssl_verify_peer(cert)
    #       true
    #     end
    #
    #     def ssl_handshake_completed
    #       $server_handshake_completed = true
    #     end
    #   end
    #
    #
    # @example This server never accepts any peers
    #
    #   module DenyServer
    #     def post_init
    #       start_tls(:verify_peer => true)
    #     end
    #
    #     def ssl_verify_peer(cert)
    #       # Do not accept the peer. This should now cause the connection to shut down
    #       # without the SSL handshake being completed.
    #       false
    #     end
    #
    #     def ssl_handshake_completed
    #       $server_handshake_completed = true
    #     end
    #   end
    #
    # @see #start_tls
    def ssl_verify_peer(cert)
    end

    # called by the framework whenever a connection (either a server or client connection) is closed.
    # The close can occur because your code intentionally closes it (using {#close_connection} and {#close_connection_after_writing}),
    # because the remote peer closed the connection, or because of a network error.
    # You may not assume that the network connection is still open and able to send or
    # receive data when the callback to unbind is made. This is intended only to give
    # you a chance to clean up associations your code may have made to the connection
    # object while it was open.
    #
    # If you want to detect which peer has closed the connection, you can override {#close_connection} in your protocol handler
    # and set an @ivar.
    #
    # @example Overriding Connection#close_connection to distinguish connections closed on our side
    #
    #   class MyProtocolHandler < EventMachine::Connection
    #
    #     # ...
    #
    #     def close_connection(*args)
    #       @intentionally_closed_connection = true
    #       super(*args)
    #     end
    #
    #     def unbind
    #       if @intentionally_closed_connection
    #         # ...
    #       end
    #     end
    #
    #     # ...
    #
    #   end
    #
    # @see #post_init
    # @see #connection_completed
    # @see file:docs/GettingStarted.md EventMachine tutorial
    def unbind
    end

    # Called by the reactor after attempting to relay incoming data to a descriptor (set as a proxy target descriptor with
    # {EventMachine.enable_proxy}) that has already been closed.
    #
    # @see EventMachine.enable_proxy
    def proxy_target_unbound
    end

    # called when the reactor finished proxying all
    # of the requested bytes.
    def proxy_completed
    end

    # EventMachine::Connection#proxy_incoming_to is called only by user code. It sets up
    # a low-level proxy relay for all data inbound for this connection, to the connection given
    # as the argument. This is essentially just a helper method for enable_proxy.
    #
    # @see EventMachine.enable_proxy
    def proxy_incoming_to(conn,bufsize=0)
      EventMachine::enable_proxy(self, conn, bufsize)
    end

    # A helper method for {EventMachine.disable_proxy}
    def stop_proxying
      EventMachine::disable_proxy(self)
    end

    # The number of bytes proxied to another connection. Reset to zero when
    # EventMachine::Connection#proxy_incoming_to is called, and incremented whenever data is proxied.
    def get_proxied_bytes
      EventMachine::get_proxied_bytes(@signature)
    end

    # EventMachine::Connection#close_connection is called only by user code, and never
    # by the event loop. You may call this method against a connection object in any
    # callback handler, whether or not the callback was made against the connection
    # you want to close. close_connection <i>schedules</i> the connection to be closed
    # at the next available opportunity within the event loop. You may not assume that
    # the connection is closed when close_connection returns. In particular, the framework
    # will callback the unbind method for the particular connection at a point shortly
    # after you call close_connection. You may assume that the unbind callback will
    # take place sometime after your call to close_connection completes. In other words,
    # the unbind callback will not re-enter your code "inside" of your call to close_connection.
    # However, it's not guaranteed that a future version of EventMachine will not change
    # this behavior.
    #
    # {#close_connection} will *silently discard* any outbound data which you have
    # sent to the connection using {EventMachine::Connection#send_data} but which has not
    # yet been sent across the network. If you want to avoid this behavior, use
    # {EventMachine::Connection#close_connection_after_writing}.
    #
    def close_connection after_writing = false
      EventMachine::close_connection @signature, after_writing
    end

    # Removes given connection from the event loop.
    # The connection's socket remains open and its file descriptor number is returned.
    def detach
      EventMachine::detach_fd @signature
    end

    def get_sock_opt level, option
      EventMachine::get_sock_opt @signature, level, option
    end

    def set_sock_opt level, optname, optval
      EventMachine::set_sock_opt @signature, level, optname, optval
    end

    # A variant of {#close_connection}.
    # All of the descriptive comments given for close_connection also apply to
    # close_connection_after_writing, *with one exception*: if the connection has
    # outbound data sent using send_dat but which has not yet been sent across the network,
    # close_connection_after_writing will schedule the connection to be closed *after*
    # all of the outbound data has been safely written to the remote peer.
    #
    # Depending on the amount of outgoing data and the speed of the network,
    # considerable time may elapse between your call to close_connection_after_writing
    # and the actual closing of the socket (at which time the unbind callback will be called
    # by the event loop). During this time, you *may not* call send_data to transmit
    # additional data (that is, the connection is closed for further writes). In very
    # rare cases, you may experience a receive_data callback after your call to {#close_connection_after_writing},
    # depending on whether incoming data was in the process of being received on the connection
    # at the moment when you called {#close_connection_after_writing}. Your protocol handler must
    # be prepared to properly deal with such data (probably by ignoring it).
    #
    # @see #close_connection
    # @see #send_data
    def close_connection_after_writing
      close_connection true
    end

    # Call this method to send data to the remote end of the network connection. It takes a single String argument,
    # which may contain binary data. Data is buffered to be sent at the end of this event loop tick (cycle).
    #
    # When used in a method that is event handler (for example, {#post_init} or {#connection_completed}, it will send
    # data to the other end of the connection that generated the event.
    # You can also call {#send_data} to write to other connections. For more information see The Chat Server Example in the
    # {file:docs/GettingStarted.md EventMachine tutorial}.
    #
    # If you want to send some data and then immediately close the connection, make sure to use {#close_connection_after_writing}
    # instead of {#close_connection}.
    #
    #
    # @param [String] data Data to send asynchronously
    #
    # @see file:docs/GettingStarted.md EventMachine tutorial
    # @see Connection#receive_data
    # @see Connection#post_init
    # @see Connection#unbind
    def send_data data
      data = data.to_s
      size = data.bytesize if data.respond_to?(:bytesize)
      size ||= data.size
      EventMachine::send_data @signature, data, size
    end

    # Returns true if the connection is in an error state, false otherwise.
    #
    # In general, you can detect the occurrence of communication errors or unexpected
    # disconnection by the remote peer by handing the {#unbind} method. In some cases, however,
    # it's useful to check the status of the connection using {#error?} before attempting to send data.
    # This function is synchronous but it will return immediately without blocking.
    #
    # @return [Boolean] true if the connection is in an error state, false otherwise
    def error?
      errno = EventMachine::report_connection_error_status(@signature)
      case errno
      when 0
        false
      when -1
        true
      else
        EventMachine::ERRNOS[errno]
      end
    end

    # Called by the event loop when a remote TCP connection attempt completes successfully.
    # You can expect to get this notification after calls to {EventMachine.connect}. Remember that EventMachine makes remote connections
    # asynchronously, just as with any other kind of network event. This method
    # is intended primarily to assist with network diagnostics. For normal protocol
    # handling, use #post_init to perform initial work on a new connection (such as sending initial set of data).
    # {Connection#post_init} will always be called. This method will only be called in case of a successful completion.
    # A connection attempt which fails will result a call to {Connection#unbind} after the failure.
    #
    # @see Connection#post_init
    # @see Connection#unbind
    # @see file:docs/GettingStarted.md EventMachine tutorial
    def connection_completed
    end

    # Call {#start_tls} at any point to initiate TLS encryption on connected streams.
    # The method is smart enough to know whether it should perform a server-side
    # or a client-side handshake. An appropriate place to call {#start_tls} is in
    # your redefined {#post_init} method, or in the {#connection_completed} handler for
    # an outbound connection.
    #
    #
    # @option args [String] :cert_chain_file (nil) local path of a readable file that contants  a chain of X509 certificates in
    #                                              the [PEM format](http://en.wikipedia.org/wiki/Privacy_Enhanced_Mail),
    #                                              with the most-resolved certificate at the top of the file, successive intermediate
    #                                              certs in the middle, and the root (or CA) cert at the bottom.
    #
    # @option args [String] :private_key_file (nil) local path of a readable file that must contain a private key in the [PEM format](http://en.wikipedia.org/wiki/Privacy_Enhanced_Mail).
    #
    # @option args [Boolean] :verify_peer (false)   indicates whether a server should request a certificate from a peer, to be verified by user code.
    #                                               If true, the {#ssl_verify_peer} callback on the {EventMachine::Connection} object is called with each certificate
    #                                               in the certificate chain provided by the peer. See documentation on {#ssl_verify_peer} for how to use this.
    #
    # @option args [Boolean] :fail_if_no_peer_cert (false)   Used in conjunction with verify_peer. If set the SSL handshake will be terminated if the peer does not provide a certificate.
    #
    #
    # @option args [String] :cipher_list ("ALL:!ADH:!LOW:!EXP:!DES-CBC3-SHA:@STRENGTH") indicates the available SSL cipher values. Default value is "ALL:!ADH:!LOW:!EXP:!DES-CBC3-SHA:@STRENGTH". Check the format of the OpenSSL cipher string at http://www.openssl.org/docs/apps/ciphers.html#CIPHER_LIST_FORMAT.
    #
    # @option args [String] :ecdh_curve (nil)  The curve for ECDHE ciphers. See available ciphers with 'openssl ecparam -list_curves'
    #
    # @option args [String] :dhparam (nil)  The local path of a file containing DH parameters for EDH ciphers in [PEM format](http://en.wikipedia.org/wiki/Privacy_Enhanced_Mail) See: 'openssl dhparam'
    #
    # @option args [Array] :ssl_version (TLSv1 TLSv1_1 TLSv1_2) indicates the allowed SSL/TLS versions. Possible values are: {SSLv2}, {SSLv3}, {TLSv1}, {TLSv1_1}, {TLSv1_2}.
    #
    # @example Using TLS with EventMachine
    #
    #  require 'rubygems'
    #  require 'eventmachine'
    #
    #  module Handler
    #    def post_init
    #      start_tls(:private_key_file => '/tmp/server.key', :cert_chain_file => '/tmp/server.crt', :verify_peer => false)
    #    end
    #  end
    #
    #   EventMachine.run do
    #    EventMachine.start_server("127.0.0.1", 9999, Handler)
    #  end
    #
    # @param [Hash] args
    #
    # @todo support passing an encryption parameter, which can be string or Proc, to get a passphrase
    # for encrypted private keys.
    # @todo support passing key material via raw strings or Procs that return strings instead of
    # just filenames.
    #
    # @see #ssl_verify_peer
    def start_tls args={}
      priv_key     = args[:private_key_file]
      cert_chain   = args[:cert_chain_file]
      verify_peer  = args[:verify_peer]
      sni_hostname = args[:sni_hostname]
      cipher_list  = args[:cipher_list]
      ssl_version  = args[:ssl_version]
      ecdh_curve   = args[:ecdh_curve]
      dhparam      = args[:dhparam]
      fail_if_no_peer_cert = args[:fail_if_no_peer_cert]

      [priv_key, cert_chain].each do |file|
        next if file.nil? or file.empty?
        raise FileNotFoundException,
        "Could not find #{file} for start_tls" unless File.exist? file
      end

      protocols_bitmask = 0
      if ssl_version.nil?
        protocols_bitmask |= EventMachine::EM_PROTO_TLSv1
        protocols_bitmask |= EventMachine::EM_PROTO_TLSv1_1
        protocols_bitmask |= EventMachine::EM_PROTO_TLSv1_2
      else
        [ssl_version].flatten.each do |p|
          case p.to_s.downcase
          when 'sslv2'
            protocols_bitmask |= EventMachine::EM_PROTO_SSLv2
          when 'sslv3'
            protocols_bitmask |= EventMachine::EM_PROTO_SSLv3
          when 'tlsv1'
            protocols_bitmask |= EventMachine::EM_PROTO_TLSv1
          when 'tlsv1_1'
            protocols_bitmask |= EventMachine::EM_PROTO_TLSv1_1
          when 'tlsv1_2'
            protocols_bitmask |= EventMachine::EM_PROTO_TLSv1_2
          else
            raise("Unrecognized SSL/TLS Protocol: #{p}")
          end
        end
      end

      EventMachine::set_tls_parms(@signature, priv_key || '', cert_chain || '', verify_peer, fail_if_no_peer_cert, sni_hostname || '', cipher_list || '', ecdh_curve || '', dhparam || '', protocols_bitmask)
      EventMachine::start_tls @signature
    end

    # If [TLS](http://en.wikipedia.org/wiki/Transport_Layer_Security) is active on the connection, returns the remote [X509 certificate](http://en.wikipedia.org/wiki/X.509)
    # as a string, in the popular [PEM format](http://en.wikipedia.org/wiki/Privacy_Enhanced_Mail). This can then be used for arbitrary validation
    # of a peer's certificate in your code.
    #
    # This should be called in/after the {#ssl_handshake_completed} callback, which indicates
    # that SSL/TLS is active. Using this callback is important, because the certificate may not
    # be available until the time it is executed. Using #post_init or #connection_completed is
    # not adequate, because the SSL handshake may still be taking place.
    #
    # This method will return `nil` if:
    #
    # * EventMachine is not built with [OpenSSL](http://www.openssl.org) support
    # * [TLS](http://en.wikipedia.org/wiki/Transport_Layer_Security) is not active on the connection
    # * TLS handshake is not yet complete
    # * Remote peer for any other reason has not presented a certificate
    #
    #
    # @example Getting peer TLS certificate information in EventMachine
    #
    #  module Handler
    #    def post_init
    #      puts "Starting TLS"
    #      start_tls
    #    end
    #
    #    def ssl_handshake_completed
    #      puts get_peer_cert
    #      close_connection
    #    end
    #
    #    def unbind
    #      EventMachine::stop_event_loop
    #    end
    #  end
    #
    #   EventMachine.run do
    #     EventMachine.connect "mail.google.com", 443, Handler
    #  end
    #
    #  # Will output:
    #  # -----BEGIN CERTIFICATE-----
    #  # MIIDIjCCAougAwIBAgIQbldpChBPqv+BdPg4iwgN8TANBgkqhkiG9w0BAQUFADBM
    #  # MQswCQYDVQQGEwJaQTElMCMGA1UEChMcVGhhd3RlIENvbnN1bHRpbmcgKFB0eSkg
    #  # THRkLjEWMBQGA1UEAxMNVGhhd3RlIFNHQyBDQTAeFw0wODA1MDIxNjMyNTRaFw0w
    #  # OTA1MDIxNjMyNTRaMGkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh
    #  # MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgSW5jMRgw
    #  # FgYDVQQDEw9tYWlsLmdvb2dsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ
    #  # AoGBALlkxdh2QXegdElukCSOV2+8PKiONIS+8Tu9K7MQsYpqtLNC860zwOPQ2NLI
    #  # 3Zp4jwuXVTrtzGuiqf5Jioh35Ig3CqDXtLyZoypjZUQcq4mlLzHlhIQ4EhSjDmA7
    #  # Ffw9y3ckSOQgdBQWNLbquHh9AbEUjmhkrYxIqKXeCnRKhv6nAgMBAAGjgecwgeQw
    #  # KAYDVR0lBCEwHwYIKwYBBQUHAwEGCCsGAQUFBwMCBglghkgBhvhCBAEwNgYDVR0f
    #  # BC8wLTAroCmgJ4YlaHR0cDovL2NybC50aGF3dGUuY29tL1RoYXd0ZVNHQ0NBLmNy
    #  # bDByBggrBgEFBQcBAQRmMGQwIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3NwLnRoYXd0
    #  # ZS5jb20wPgYIKwYBBQUHMAKGMmh0dHA6Ly93d3cudGhhd3RlLmNvbS9yZXBvc2l0
    #  # b3J5L1RoYXd0ZV9TR0NfQ0EuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEF
    #  # BQADgYEAsRwpLg1dgCR1gYDK185MFGukXMeQFUvhGqF8eT/CjpdvezyKVuz84gSu
    #  # 6ccMXgcPQZGQN/F4Xug+Q01eccJjRSVfdvR5qwpqCj+6BFl5oiKDBsveSkrmL5dz
    #  # s2bn7TdTSYKcLeBkjXxDLHGBqLJ6TNCJ3c4/cbbG5JhGvoema94=
    #  # -----END CERTIFICATE-----
    #
    # You can do whatever you want with the certificate String, such as load it
    # as a certificate object using the OpenSSL library, and check its fields.
    #
    # @return [String] the remote [X509 certificate](http://en.wikipedia.org/wiki/X.509), in the popular [PEM format](http://en.wikipedia.org/wiki/Privacy_Enhanced_Mail),
    #                  if TLS is active on the connection
    #
    # @see Connection#start_tls
    # @see Connection#ssl_handshake_completed
    def get_peer_cert
      EventMachine::get_peer_cert @signature
    end

    def get_cipher_bits
      EventMachine::get_cipher_bits @signature
    end

    def get_cipher_name
      EventMachine::get_cipher_name @signature
    end

    def get_cipher_protocol
      EventMachine::get_cipher_protocol @signature
    end

    def get_sni_hostname
      EventMachine::get_sni_hostname @signature
    end

    # Sends UDP messages.
    #
    # This method may be called from any Connection object that refers
    # to an open datagram socket (see EventMachine#open_datagram_socket).
    # The method sends a UDP (datagram) packet containing the data you specify,
    # to a remote peer specified by the IP address and port that you give
    # as parameters to the method.
    # Observe that you may send a zero-length packet (empty string).
    # However, you may not send an arbitrarily-large data packet because
    # your operating system will enforce a platform-specific limit on
    # the size of the outbound packet. (Your kernel
    # will respond in a platform-specific way if you send an overlarge
    # packet: some will send a truncated packet, some will complain, and
    # some will silently drop your request).
    # On LANs, it's usually OK to send datagrams up to about 4000 bytes in length,
    # but to be really safe, send messages smaller than the Ethernet-packet
    # size (typically about 1400 bytes). Some very restrictive WANs
    # will either drop or truncate packets larger than about 500 bytes.
    #
    # @param [String] data              Data to send asynchronously
    # @param [String] recipient_address IP address of the recipient
    # @param [String] recipient_port    Port of the recipient
    def send_datagram data, recipient_address, recipient_port
      data = data.to_s
      size = data.bytesize if data.respond_to?(:bytesize)
      size ||= data.size
      EventMachine::send_datagram @signature, data, size, recipient_address, Integer(recipient_port)
    end


    # This method is used with stream-connections to obtain the identity
    # of the remotely-connected peer. If a peername is available, this method
    # returns a sockaddr structure. The method returns nil if no peername is available.
    # You can use Socket.unpack_sockaddr_in and its variants to obtain the
    # values contained in the peername structure returned from #get_peername.
    #
    # @example How to get peer IP address and port with EventMachine
    #
    #  require 'socket'
    #
    #  module Handler
    #    def receive_data data
    #      port, ip = Socket.unpack_sockaddr_in(get_peername)
    #      puts "got #{data.inspect} from #{ip}:#{port}"
    #    end
    #  end
    def get_peername
      EventMachine::get_peername @signature
    end

    # Used with stream-connections to obtain the identity
    # of the local side of the connection. If a local name is available, this method
    # returns a sockaddr structure. The method returns nil if no local name is available.
    # You can use {Socket.unpack_sockaddr_in} and its variants to obtain the
    # values contained in the local-name structure returned from this method.
    #
    # @example
    #
    #  require 'socket'
    #
    #  module Handler
    #    def receive_data data
    #      port, ip = Socket.unpack_sockaddr_in(get_sockname)
    #      puts "got #{data.inspect}"
    #    end
    #  end
    def get_sockname
      EventMachine::get_sockname @signature
    end

    # Returns the PID (kernel process identifier) of a subprocess
    # associated with this Connection object. For use with {EventMachine.popen}
    # and similar methods. Returns nil when there is no meaningful subprocess.
    #
    # @return [Integer]
    def get_pid
      EventMachine::get_subprocess_pid @signature
    end

    # Returns a subprocess exit status. Only useful for {EventMachine.popen}. Call it in your
    # {#unbind} handler.
    #
    # @return [Integer]
    def get_status
      EventMachine::get_subprocess_status @signature
    end

    # The number of seconds since the last send/receive activity on this connection.
    def get_idle_time
      EventMachine::get_idle_time @signature
    end

    # comm_inactivity_timeout returns the current value (float in seconds) of the inactivity-timeout
    # property of network-connection and datagram-socket objects. A nonzero value
    # indicates that the connection or socket will automatically be closed if no read or write
    # activity takes place for at least that number of seconds.
    # A zero value (the default) specifies that no automatic timeout will take place.
    def comm_inactivity_timeout
      EventMachine::get_comm_inactivity_timeout @signature
    end

    # Allows you to set the inactivity-timeout property for
    # a network connection or datagram socket. Specify a non-negative float value in seconds.
    # If the value is greater than zero, the connection or socket will automatically be closed
    # if no read or write activity takes place for at least that number of seconds.
    # Specify a value of zero to indicate that no automatic timeout should take place.
    # Zero is the default value.
    def comm_inactivity_timeout= value
      EventMachine::set_comm_inactivity_timeout @signature, value.to_f
    end
    alias set_comm_inactivity_timeout comm_inactivity_timeout=

      # The duration after which a TCP connection in the connecting state will fail.
      # It is important to distinguish this value from {EventMachine::Connection#comm_inactivity_timeout},
      # which looks at how long since data was passed on an already established connection.
      # The value is a float in seconds.
      #
      # @return [Float] The duration after which a TCP connection in the connecting state will fail, in seconds.
      def pending_connect_timeout
        EventMachine::get_pending_connect_timeout @signature
      end

    # Sets the duration after which a TCP connection in a
    # connecting state will fail.
    #
    # @param [Float, #to_f] value Connection timeout in seconds
    def pending_connect_timeout= value
      EventMachine::set_pending_connect_timeout @signature, value.to_f
    end
    alias set_pending_connect_timeout pending_connect_timeout=

      # Reconnect to a given host/port with the current instance
      #
      # @param [String] server Hostname or IP address
      # @param [Integer] port  Port to reconnect to
      def reconnect server, port
        EventMachine::reconnect server, port, self
      end


    # Like {EventMachine::Connection#send_data}, this sends data to the remote end of
    # the network connection. {EventMachine::Connection#send_file_data} takes a
    # filename as an argument, though, and sends the contents of the file, in one
    # chunk.
    #
    # @param [String] filename Local path of the file to send
    #
    # @see #send_data
    # @author Kirk Haines
    def send_file_data filename
      EventMachine::send_file_data @signature, filename
    end

    # Open a file on the filesystem and send it to the remote peer. This returns an
    # object of type {EventMachine::Deferrable}. The object's callbacks will be executed
    # on the reactor main thread when the file has been completely scheduled for
    # transmission to the remote peer. Its errbacks will be called in case of an error (such as file-not-found).
    # This method employs various strategies to achieve the fastest possible performance,
    # balanced against minimum consumption of memory.
    #
    # Warning: this feature has an implicit dependency on an outboard extension,
    # evma_fastfilereader. You must install this extension in order to use {#stream_file_data}
    # with files larger than a certain size (currently 8192 bytes).
    #
    # @option args [Boolean] :http_chunks (false) If true, this method will stream the file data in a format
    #                                             compatible with the HTTP chunked-transfer encoding
    #
    # @param [String] filename Local path of the file to stream
    # @param [Hash] args Options
    #
    # @return [EventMachine::Deferrable]
    def stream_file_data filename, args={}
      EventMachine::FileStreamer.new( self, filename, args )
    end

    # Watches connection for readability. Only possible if the connection was created
    # using {EventMachine.attach} and had {EventMachine.notify_readable}/{EventMachine.notify_writable} defined on the handler.
    #
    # @see #notify_readable?
    def notify_readable= mode
      EventMachine::set_notify_readable @signature, mode
    end

    # @return [Boolean] true if the connection is being watched for readability.
    def notify_readable?
      EventMachine::is_notify_readable @signature
    end

    # Watches connection for writeability. Only possible if the connection was created
    # using {EventMachine.attach} and had {EventMachine.notify_readable}/{EventMachine.notify_writable} defined on the handler.
    #
    # @see #notify_writable?
    def notify_writable= mode
      EventMachine::set_notify_writable @signature, mode
    end

    # Returns true if the connection is being watched for writability.
    def notify_writable?
      EventMachine::is_notify_writable @signature
    end

    # Pause a connection so that {#send_data} and {#receive_data} events are not fired until {#resume} is called.
    # @see #resume
    def pause
      EventMachine::pause_connection @signature
    end

    # Resume a connection's {#send_data} and {#receive_data} events.
    # @see #pause
    def resume
      EventMachine::resume_connection @signature
    end

    # @return [Boolean] true if the connect was paused using {EventMachine::Connection#pause}.
    # @see #pause
    # @see #resume
    def paused?
      EventMachine::connection_paused? @signature
    end
  end
end
