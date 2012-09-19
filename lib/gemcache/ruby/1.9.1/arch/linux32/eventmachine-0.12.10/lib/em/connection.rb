module EventMachine
  class FileNotFoundException < Exception # :nodoc:
  end

  # EventMachine::Connection is a class that is instantiated
  # by EventMachine's processing loop whenever a new connection
  # is created. (New connections can be either initiated locally
  # to a remote server or accepted locally from a remote client.)
  # When a Connection object is instantiated, it <i>mixes in</i>
  # the functionality contained in the user-defined module
  # specified in calls to EventMachine#connect or EventMachine#start_server.
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
  # which may be called by the event loop are: post_init, receive_data,
  # and unbind. All of the other instance methods defined here are called
  # only by user code.
  #
  class Connection
    attr_accessor :signature # :nodoc:

    # Override .new so subclasses don't have to call super and can ignore
    # connection-specific arguments
    #
    def self.new(sig, *args) #:nodoc:
      allocate.instance_eval do
        # Store signature
        @signature = sig
        associate_callback_target sig

        # Call a superclass's #initialize if it has one
        initialize(*args)

        # post initialize callback
        post_init

        self
      end
    end

    # Stubbed initialize so legacy superclasses can safely call super
    #
    def initialize(*args) #:nodoc:
    end

    # def associate_callback_target(sig) #:nodoc:
    #   # no-op for the time being, to match similar no-op in rubymain.cpp
    # end

    # EventMachine::Connection#post_init is called by the event loop
    # immediately after the network connection has been established,
    # and before resumption of the network loop.
    # This method is generally not called by user code, but is called automatically
    # by the event loop. The base-class implementation is a no-op.
    # This is a very good place to initialize instance variables that will
    # be used throughout the lifetime of the network connection.
    #
    def post_init
    end

    # EventMachine::Connection#receive_data is called by the event loop
    # whenever data has been received by the network connection.
    # It is never called by user code.
    # receive_data is called with a single parameter, a String containing
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
    # The base-class implementation of receive_data (which will be invoked if
    # you don't redefine it) simply prints the size of each incoming data packet
    # to stdout.
    #
    def receive_data data
      puts "............>>>#{data.length}"
    end

    # #ssl_handshake_completed is called by EventMachine when the SSL/TLS handshake has
    # been completed, as a result of calling #start_tls to initiate SSL/TLS on the connection.
    #
    # This callback exists because #post_init and #connection_completed are <b>not</b> reliable
    # for indicating when an SSL/TLS connection is ready to have it's certificate queried for.
    #
    # See #get_peer_cert for application and example.
    def ssl_handshake_completed
    end

    # #ssl_verify_peer is called by EventMachine when :verify_peer => true has been passed to #start_tls.
    # It will be called with each certificate in the certificate chain provided by the remote peer.
    # The cert will be passed as a String in PEM format, the same as in #get_peer_cert. It is up to user defined
    # code to perform a check on the certificates. The return value from this callback is used to accept or deny the peer.
    # A return value that is not nil or false triggers acceptance. If the peer is not accepted, the connection
    # will be subsequently closed. See 'tests/test_ssl_verify.rb' for a simple example.
    def ssl_verify_peer(cert)
    end

    # EventMachine::Connection#unbind is called by the framework whenever a connection
    # (either a server or client connection) is closed. The close can occur because
    # your code intentionally closes it (see close_connection and close_connection_after_writing),
    # because the remote peer closed the connection, or because of a network error.
    # You may not assume that the network connection is still open and able to send or
    # receive data when the callback to unbind is made. This is intended only to give
    # you a chance to clean up associations your code may have made to the connection
    # object while it was open.
    #
    def unbind
    end

    # EventMachine::Connection#proxy_target_unbound is called by the reactor after attempting
    # to relay incoming data to a descriptor (set as a proxy target descriptor with
    # EventMachine::enable_proxy) that has already been closed.
    def proxy_target_unbound
    end

    # EventMachine::Connection#proxy_incoming_to is called only by user code. It sets up
    # a low-level proxy relay for all data inbound for this connection, to the connection given
    # as the argument. This is essentially just a helper method for enable_proxy.
    # See EventMachine::enable_proxy documentation for details.
    def proxy_incoming_to(conn,bufsize=0)
      EventMachine::enable_proxy(self, conn, bufsize)
    end

    # Helper method for EventMachine::disable_proxy(self)
    def stop_proxying
      EventMachine::disable_proxy(self)
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
    # close_connection will <i>silently discard</i> any outbound data which you have
    # sent to the connection using EventMachine::Connection#send_data but which has not
    # yet been sent across the network. If you want to avoid this behavior, use
    # EventMachine::Connection#close_connection_after_writing.
    #
    def close_connection after_writing = false
      EventMachine::close_connection @signature, after_writing
    end

    # EventMachine::Connection#detach will remove the given connection from the event loop.
    # The connection's socket remains open and its file descriptor number is returned
    def detach
      EventMachine::detach_fd @signature
    end

    def get_sock_opt level, option
      EventMachine::get_sock_opt @signature, level, option
    end

    # EventMachine::Connection#close_connection_after_writing is a variant of close_connection.
    # All of the descriptive comments given for close_connection also apply to
    # close_connection_after_writing, <i>with one exception:</i> If the connection has
    # outbound data sent using send_dat but which has not yet been sent across the network,
    # close_connection_after_writing will schedule the connection to be closed <i>after</i>
    # all of the outbound data has been safely written to the remote peer.
    #
    # Depending on the amount of outgoing data and the speed of the network,
    # considerable time may elapse between your call to close_connection_after_writing
    # and the actual closing of the socket (at which time the unbind callback will be called
    # by the event loop). During this time, you <i>may not</i> call send_data to transmit
    # additional data (that is, the connection is closed for further writes). In very
    # rare cases, you may experience a receive_data callback after your call to close_connection_after_writing,
    # depending on whether incoming data was in the process of being received on the connection
    # at the moment when you called close_connection_after_writing. Your protocol handler must
    # be prepared to properly deal with such data (probably by ignoring it).
    #
    def close_connection_after_writing
      close_connection true
    end

    # EventMachine::Connection#send_data is only called by user code, never by
    # the event loop. You call this method to send data to the remote end of the
    # network connection. send_data is called with a single String argument, which
    # may of course contain binary data. You can call send_data any number of times.
    # send_data is an instance method of an object derived from EventMachine::Connection
    # and containing your mixed-in handler code), so if you call it without qualification
    # within a callback function, the data will be sent to the same network connection
    # that generated the callback. Calling self.send_data is exactly equivalent.
    #
    # You can also call send_data to write to a connection <i>other than the one
    # whose callback you are calling send_data from.</i> This is done by recording
    # the value of the connection in any callback function (the value self), in any
    # variable visible to other callback invocations on the same or different
    # connection objects. (Need an example to make that clear.)
    #
    def send_data data
      data = data.to_s
      size = data.bytesize if data.respond_to?(:bytesize)
      size ||= data.size
      EventMachine::send_data @signature, data, size
    end

    # Returns true if the connection is in an error state, false otherwise.
    # In general, you can detect the occurrence of communication errors or unexpected
    # disconnection by the remote peer by handing the #unbind method. In some cases, however,
    # it's useful to check the status of the connection using #error? before attempting to send data.
    # This function is synchronous: it will return immediately without blocking.
    #
    #
    def error?
      EventMachine::report_connection_error_status(@signature) != 0
    end

    # #connection_completed is called by the event loop when a remote TCP connection
    # attempt completes successfully. You can expect to get this notification after calls
    # to EventMachine#connect. Remember that EventMachine makes remote connections
    # asynchronously, just as with any other kind of network event. #connection_completed
    # is intended primarily to assist with network diagnostics. For normal protocol
    # handling, use #post_init to perform initial work on a new connection (such as
    # send an initial set of data).
    # #post_init will always be called. #connection_completed will only be called in case
    # of a successful completion. A connection-attempt which fails will receive a call
    # to #unbind after the failure.
    def connection_completed
    end

    # Call #start_tls at any point to initiate TLS encryption on connected streams.
    # The method is smart enough to know whether it should perform a server-side
    # or a client-side handshake. An appropriate place to call #start_tls is in
    # your redefined #post_init method, or in the #connection_completed handler for
    # an outbound connection.
    #
    # #start_tls takes an optional parameter hash that allows you to specify certificate
    # and other options to be used with this Connection object. Here are the currently-supported
    # options:
    #
    # * :cert_chain_file :
    # takes a String, which is interpreted as the name of a readable file in the
    # local filesystem. The file is expected to contain a chain of X509 certificates in
    # PEM format, with the most-resolved certificate at the top of the file, successive
    # intermediate certs in the middle, and the root (or CA) cert at the bottom.
    #
    # * :private_key_file :
    # takes a String, which is interpreted as the name of a readable file in the
    # local filesystem. The file must contain a private key in PEM format.
    #
    # * :verify_peer :
    # takes either true or false. Default is false. This indicates whether a server should request a
    # certificate from a peer, to be verified by user code. If true, the #ssl_verify_peer callback
    # on the Connection object is called with each certificate in the certificate chain provided by
    # the peer. See documentation on #ssl_verify_peer for how to use this.
    #
    # === Usage example:
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
    #  EM.run {
    #    EM.start_server("127.0.0.1", 9999, Handler)
    #  }
    #
    #--
    # TODO: support passing an encryption parameter, which can be string or Proc, to get a passphrase
    # for encrypted private keys.
    # TODO: support passing key material via raw strings or Procs that return strings instead of
    # just filenames.
    # What will get nasty is whether we have to define a location for storing this stuff as files.
    # In general, the OpenSSL interfaces for dealing with certs and keys in files are much better
    # behaved than the ones for raw chunks of memory.
    #
    def start_tls args={}
      priv_key, cert_chain, verify_peer = args.values_at(:private_key_file, :cert_chain_file, :verify_peer)

      [priv_key, cert_chain].each do |file|
        next if file.nil? or file.empty?
        raise FileNotFoundException,
          "Could not find #{file} for start_tls" unless File.exists? file
      end

      EventMachine::set_tls_parms(@signature, priv_key || '', cert_chain || '', verify_peer)
      EventMachine::start_tls @signature
    end

    # If SSL/TLS is active on the connection, #get_peer_cert returns the remote X509 certificate
    # as a String, in the popular PEM format. This can then be used for arbitrary validation
    # of a peer's certificate in your code.
    #
    # This should be called in/after the #ssl_handshake_completed callback, which indicates
    # that SSL/TLS is active. Using this callback is important, because the certificate may not
    # be available until the time it is executed. Using #post_init or #connection_completed is
    # not adequate, because the SSL handshake may still be taking place.
    #
    # #get_peer_cert will return <b>nil</b> if:
    #
    # * EventMachine is not built with OpenSSL support
    # * SSL/TLS is not active on the connection
    # * SSL/TLS handshake is not yet complete
    # * Remote peer for any other reason has not presented a certificate
    #
    # === Example:
    #
    #  module Handler
    #
    #   def post_init
    #     puts "Starting TLS"
    #     start_tls
    #   end
    #
    #   def ssl_handshake_completed
    #     puts get_peer_cert
    #     close_connection
    #   end
    #
    #   def unbind
    #     EventMachine::stop_event_loop
    #   end
    #
    #  end
    #
    #  EM.run {
    #   EventMachine::connect "mail.google.com", 443, Handler
    #  }
    #
    # Output:
    #  -----BEGIN CERTIFICATE-----
    #  MIIDIjCCAougAwIBAgIQbldpChBPqv+BdPg4iwgN8TANBgkqhkiG9w0BAQUFADBM
    #  MQswCQYDVQQGEwJaQTElMCMGA1UEChMcVGhhd3RlIENvbnN1bHRpbmcgKFB0eSkg
    #  THRkLjEWMBQGA1UEAxMNVGhhd3RlIFNHQyBDQTAeFw0wODA1MDIxNjMyNTRaFw0w
    #  OTA1MDIxNjMyNTRaMGkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh
    #  MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgSW5jMRgw
    #  FgYDVQQDEw9tYWlsLmdvb2dsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ
    #  AoGBALlkxdh2QXegdElukCSOV2+8PKiONIS+8Tu9K7MQsYpqtLNC860zwOPQ2NLI
    #  3Zp4jwuXVTrtzGuiqf5Jioh35Ig3CqDXtLyZoypjZUQcq4mlLzHlhIQ4EhSjDmA7
    #  Ffw9y3ckSOQgdBQWNLbquHh9AbEUjmhkrYxIqKXeCnRKhv6nAgMBAAGjgecwgeQw
    #  KAYDVR0lBCEwHwYIKwYBBQUHAwEGCCsGAQUFBwMCBglghkgBhvhCBAEwNgYDVR0f
    #  BC8wLTAroCmgJ4YlaHR0cDovL2NybC50aGF3dGUuY29tL1RoYXd0ZVNHQ0NBLmNy
    #  bDByBggrBgEFBQcBAQRmMGQwIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3NwLnRoYXd0
    #  ZS5jb20wPgYIKwYBBQUHMAKGMmh0dHA6Ly93d3cudGhhd3RlLmNvbS9yZXBvc2l0
    #  b3J5L1RoYXd0ZV9TR0NfQ0EuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEF
    #  BQADgYEAsRwpLg1dgCR1gYDK185MFGukXMeQFUvhGqF8eT/CjpdvezyKVuz84gSu
    #  6ccMXgcPQZGQN/F4Xug+Q01eccJjRSVfdvR5qwpqCj+6BFl5oiKDBsveSkrmL5dz
    #  s2bn7TdTSYKcLeBkjXxDLHGBqLJ6TNCJ3c4/cbbG5JhGvoema94=
    #  -----END CERTIFICATE-----
    #
    # You can do whatever you want with the certificate String, such as load it
    # as a certificate object using the OpenSSL library, and check it's fields.
    def get_peer_cert
      EventMachine::get_peer_cert @signature
    end


    # send_datagram is for sending UDP messages.
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
    #--
    # Added the Integer wrapper around the port parameter per suggestion by
    # Matthieu Riou, after he passed a String and spent hours tearing his hair out.
    #
    def send_datagram data, recipient_address, recipient_port
      data = data.to_s
      EventMachine::send_datagram @signature, data, data.length, recipient_address, Integer(recipient_port)
    end


    # #get_peername is used with stream-connections to obtain the identity
    # of the remotely-connected peer. If a peername is available, this method
    # returns a sockaddr structure. The method returns nil if no peername is available.
    # You can use Socket.unpack_sockaddr_in and its variants to obtain the
    # values contained in the peername structure returned from #get_peername.
    #
    #  require 'socket'
    #  module Handler
    #    def receive_data data
    #      port, ip = Socket.unpack_sockaddr_in(get_peername)
    #      puts "got #{data.inspect} from #{ip}:#{port}"
    #    end
    #  end
    def get_peername
      EventMachine::get_peername @signature
    end

    # #get_sockname is used with stream-connections to obtain the identity
    # of the local side of the connection. If a local name is available, this method
    # returns a sockaddr structure. The method returns nil if no local name is available.
    # You can use Socket#unpack_sockaddr_in and its variants to obtain the
    # values contained in the local-name structure returned from #get_sockname.
    def get_sockname
      EventMachine::get_sockname @signature
    end

    # Returns the PID (kernel process identifier) of a subprocess
    # associated with this Connection object. For use with EventMachine#popen
    # and similar methods. Returns nil when there is no meaningful subprocess.
    #--
    #
    def get_pid
      EventMachine::get_subprocess_pid @signature
    end

    # Returns a subprocess exit status. Only useful for #popen. Call it in your
    # #unbind handler.
    #
    def get_status
      EventMachine::get_subprocess_status @signature
    end

    # comm_inactivity_timeout returns the current value (float in seconds) of the inactivity-timeout
    # property of network-connection and datagram-socket objects. A nonzero value
    # indicates that the connection or socket will automatically be closed if no read or write
    # activity takes place for at least that number of seconds.
    # A zero value (the default) specifies that no automatic timeout will take place.
    def comm_inactivity_timeout
      EventMachine::get_comm_inactivity_timeout @signature
    end

    # Alias for #set_comm_inactivity_timeout.
    def comm_inactivity_timeout= value
      self.set_comm_inactivity_timeout value
    end

    # comm_inactivity_timeout= allows you to set the inactivity-timeout property for
    # a network connection or datagram socket. Specify a non-negative float value in seconds.
    # If the value is greater than zero, the connection or socket will automatically be closed
    # if no read or write activity takes place for at least that number of seconds.
    # Specify a value of zero to indicate that no automatic timeout should take place.
    # Zero is the default value.
    def set_comm_inactivity_timeout value
      EventMachine::set_comm_inactivity_timeout @signature, value.to_f
    end

    # pending_connect_timeout is the duration after which a TCP connection in the connecting 
    # state will fail. It is important to distinguish this value from comm_inactivity_timeout,
    # which looks at how long since data was passed on an already established connection.
    # The value is a float in seconds.
    def pending_connect_timeout
      EventMachine::get_pending_connect_timeout @signature
    end

    # Alias for #set_pending_connect_timeout.
    def pending_connect_timeout= value
      self.set_pending_connect_timeout value
    end

    # set_pending_connect_timeout sets the duration after which a TCP connection in a
    # connecting state will fail. Takes a float in seconds.
    def set_pending_connect_timeout value
      EventMachine::set_pending_connect_timeout @signature, value.to_f
    end

    # Reconnect to a given host/port with the current EventMachine::Connection instance
    def reconnect server, port
      EventMachine::reconnect server, port, self
    end


    # Like EventMachine::Connection#send_data, this sends data to the remote end of
    # the network connection.  EventMachine::Connection@send_file_data takes a
    # filename as an argument, though, and sends the contents of the file, in one
    # chunk. Contributed by Kirk Haines.
    #
    def send_file_data filename
      EventMachine::send_file_data @signature, filename
    end

    # Open a file on the filesystem and send it to the remote peer. This returns an
    # object of type EventMachine::Deferrable. The object's callbacks will be executed
    # on the reactor main thread when the file has been completely scheduled for
    # transmission to the remote peer. Its errbacks will be called in case of an error
    # (such as file-not-found). #stream_file_data employs various strategems to achieve
    # the fastest possible performance, balanced against minimum consumption of memory.
    #
    # You can control the behavior of #stream_file_data with the optional arguments parameter.
    # Currently-supported arguments are:
    # :http_chunks, a boolean flag which defaults false. If true, this flag streams the
    # file data in a format compatible with the HTTP chunked-transfer encoding.
    #
    # Warning: this feature has an implicit dependency on an outboard extension,
    # evma_fastfilereader. You must install this extension in order to use #stream_file_data
    # with files larger than a certain size (currently 8192 bytes).
    #
    def stream_file_data filename, args={}
      EventMachine::FileStreamer.new( self, filename, args )
    end

    # Enable notify_readable callbacks on this connection. Only possible if the connection was created
    # using EM.attach and had notify_readable/notify_writable defined on the handler.
    def notify_readable= mode
      EventMachine::set_notify_readable @signature, mode
    end

    # Returns true if the connection is being watched for readability.
    def notify_readable?
      EventMachine::is_notify_readable @signature
    end

    # Enable notify_writable callbacks on this connection. Only possible if the connection was created
    # using EM.attach and had notify_readable/notify_writable defined on the handler.
    def notify_writable= mode
      EventMachine::set_notify_writable @signature, mode
    end

    # Returns true if the connection is being watched for writability.
    def notify_writable?
      EventMachine::is_notify_writable @signature
    end

    # Pause a connection so that #send_data and #receive_data events are not fired until #resume is called.
    def pause
      EventMachine::pause_connection @signature
    end

    # Resume a connection's #send_data and #receive_data events.
    def resume
      EventMachine::resume_connection @signature
    end

    # True if the connect was paused using #pause.
    def paused?
      EventMachine::connection_paused? @signature
    end
  end
end