require 'net/ssh/loggable'
require 'net/ssh/connection/constants'
require 'net/ssh/connection/term'

module Net 
  module SSH 
    module Connection

      # The channel abstraction. Multiple "channels" can be multiplexed onto a
      # single SSH channel, each operating independently and seemingly in parallel.
      # This class represents a single such channel. Most operations performed
      # with the Net::SSH library will involve using one or more channels.
      #
      # Channels are intended to be used asynchronously. You request that one be
      # opened (via Connection::Session#open_channel), and when it is opened, your
      # callback is invoked. Then, you set various other callbacks on the newly
      # opened channel, which are called in response to the corresponding events.
      # Programming with Net::SSH works best if you think of your programs as
      # state machines. Complex programs are best implemented as objects that
      # wrap a channel. See Net::SCP and Net::SFTP for examples of how complex
      # state machines can be built on top of the SSH protocol.
      #
      #   ssh.open_channel do |channel|
      #     channel.exec("/invoke/some/command") do |ch, success|
      #       abort "could not execute command" unless success
      #
      #       channel.on_data do |ch, data|
      #         puts "got stdout: #{data}"
      #         channel.send_data "something for stdin\n"
      #       end
      #
      #       channel.on_extended_data do |ch, type, data|
      #         puts "got stderr: #{data}"
      #       end
      #
      #       channel.on_close do |ch|
      #         puts "channel is closing!"
      #       end
      #     end
      #   end
      #
      #   ssh.loop
      #
      # Channels also have a basic hash-like interface, that allows programs to
      # store arbitrary state information on a channel object. This helps simplify
      # the writing of state machines, especially when you may be juggling
      # multiple open channels at the same time.
      #
      # Note that data sent across SSH channels are governed by maximum packet
      # sizes and maximum window sizes. These details are managed internally
      # by Net::SSH::Connection::Channel, so you may remain blissfully ignorant
      # if you so desire, but you can always inspect the current maximums, as
      # well as the remaining window size, using the reader attributes for those
      # values.
      class Channel
        include Loggable
        include Constants
    
        # The local id for this channel, assigned by the Net::SSH::Connection::Session instance.
        attr_reader :local_id
    
        # The remote id for this channel, assigned by the remote host.
        attr_reader :remote_id
    
        # The type of this channel, usually "session".
        attr_reader :type
    
        # The underlying Net::SSH::Connection::Session instance that supports this channel.
        attr_reader :connection
    
        # The maximum packet size that the local host can receive.
        attr_reader :local_maximum_packet_size
    
        # The maximum amount of data that the local end of this channel can
        # receive. This is a total, not per-packet.
        attr_reader :local_maximum_window_size
    
        # The maximum packet size that the remote host can receive.
        attr_reader :remote_maximum_packet_size
    
        # The maximum amount of data that the remote end of this channel can
        # receive. This is a total, not per-packet.
        attr_reader :remote_maximum_window_size
    
        # This is the remaining window size on the local end of this channel. When
        # this reaches zero, no more data can be received.
        attr_reader :local_window_size
    
        # This is the remaining window size on the remote end of this channel. When
        # this reaches zero, no more data can be sent.
        attr_reader :remote_window_size
    
        # A hash of properties for this channel. These can be used to store state
        # information about this channel. See also #[] and #[]=.
        attr_reader :properties
    
        # The output buffer for this channel. Data written to the channel is
        # enqueued here, to be written as CHANNEL_DATA packets during each pass of
        # the event loop. See Connection::Session#process and #enqueue_pending_output.
        attr_reader :output #:nodoc:
    
        # The list of pending requests. Each time a request is sent which requires
        # a reply, the corresponding callback is pushed onto this queue. As responses
        # arrive, they are shifted off the front and handled.
        attr_reader :pending_requests #:nodoc:
    
        # Instantiates a new channel on the given connection, of the given type,
        # and with the given id. If a block is given, it will be remembered until
        # the channel is confirmed open by the server, and will be invoked at
        # that time (see #do_open_confirmation).
        #
        # This also sets the default maximum packet size and maximum window size.
        def initialize(connection, type, local_id, max_pkt_size = 0x8000, max_win_size = 0x20000, &on_confirm_open)
          self.logger = connection.logger
    
          @connection = connection
          @type       = type
          @local_id   = local_id
    
          @local_maximum_packet_size = max_pkt_size
          @local_window_size = @local_maximum_window_size = max_win_size
    
          @on_confirm_open = on_confirm_open
    
          @output = Buffer.new
    
          @properties = {}
    
          @pending_requests = []
          @on_open_failed = @on_data = @on_extended_data = @on_process = @on_close = @on_eof = nil
          @on_request = {}
          @closing = @eof = @sent_eof = @local_closed = @remote_closed = false
        end
    
        # A shortcut for accessing properties of the channel (see #properties).
        def [](name)
          @properties[name]
        end
    
        # A shortcut for setting properties of the channel (see #properties).
        def []=(name, value)
          @properties[name] = value
        end
    
        # Syntactic sugar for executing a command. Sends a channel request asking
        # that the given command be invoked. If the block is given, it will be
        # called when the server responds. The first parameter will be the
        # channel, and the second will be true or false, indicating whether the
        # request succeeded or not. In this case, success means that the command
        # is being executed, not that it has completed, and failure means that the
        # command altogether failed to be executed.
        #
        #   channel.exec "ls -l /home" do |ch, success|
        #     if success
        #       puts "command has begun executing..."
        #       # this is a good place to hang callbacks like #on_data...
        #     else
        #       puts "alas! the command could not be invoked!"
        #     end
        #   end
        def exec(command, &block)
          send_channel_request("exec", :string, command, &block)
        end
    
        # Syntactic sugar for requesting that a subsystem be started. Subsystems
        # are a way for other protocols (like SFTP) to be run, using SSH as
        # the transport. Generally, you'll never need to call this directly unless
        # you are the implementor of something that consumes an SSH subsystem, like
        # SFTP.
        #
        #   channel.subsystem("sftp") do |ch, success|
        #     if success
        #       puts "subsystem successfully started"
        #     else
        #       puts "subsystem could not be started"
        #     end
        #   end
        def subsystem(subsystem, &block)
          send_channel_request("subsystem", :string, subsystem, &block)
        end
    
        # Syntactic sugar for setting an environment variable in the remote
        # process' environment. Note that for security reasons, the server may
        # refuse to set certain environment variables, or all, at the server's
        # discretion. If you are connecting to an OpenSSH server, you will
        # need to update the AcceptEnv setting in the sshd_config to include the
        # environment variables you want to send.
        #
        #   channel.env "PATH", "/usr/local/bin"
        def env(variable_name, variable_value, &block)
          send_channel_request("env", :string, variable_name, :string, variable_value, &block)
        end
    
        # A hash of the valid PTY options (see #request_pty).
        VALID_PTY_OPTIONS = { term: "xterm",
                              chars_wide: 80,
                              chars_high: 24,
                              pixels_wide: 640,
                              pixels_high: 480,
                              modes: {} }
    
        # Requests that a pseudo-tty (or "pty") be made available for this channel.
        # This is useful when you want to invoke and interact with some kind of
        # screen-based program (e.g., vim, or some menuing system).
        #
        # Note, that without a pty some programs (e.g. sudo, or subversion) on
        # some systems, will not be able to run interactively, and will error
        # instead of prompt if they ever need some user interaction.
        #
        # Note, too, that when a pty is requested, user's shell configuration
        # scripts (.bashrc and such) are not run by default, whereas they are
        # run when a pty is not present.
        #
        #   channel.request_pty do |ch, success|
        #     if success
        #       puts "pty successfully obtained"
        #     else
        #       puts "could not obtain pty"
        #     end
        #   end
        def request_pty(opts={}, &block)
          extra = opts.keys - VALID_PTY_OPTIONS.keys
          raise ArgumentError, "invalid option(s) to request_pty: #{extra.inspect}" if extra.any?
    
          opts = VALID_PTY_OPTIONS.merge(opts)
    
          modes = opts[:modes].inject(Buffer.new) do |memo, (mode, data)|
            memo.write_byte(mode).write_long(data)
          end
          # mark the end of the mode opcode list with a 0 byte
          modes.write_byte(0)
    
          send_channel_request("pty-req", :string, opts[:term],
            :long, opts[:chars_wide], :long, opts[:chars_high],
            :long, opts[:pixels_wide], :long, opts[:pixels_high],
            :string, modes.to_s, &block)
        end
    
        # Sends data to the channel's remote endpoint. This usually has the
        # effect of sending the given string to the remote process' stdin stream.
        # Note that it does not immediately send the data across the channel,
        # but instead merely appends the given data to the channel's output buffer,
        # preparatory to being packaged up and sent out the next time the connection
        # is accepting data. (A connection might not be accepting data if, for
        # instance, it has filled its data window and has not yet been resized by
        # the remote end-point.)
        #
        # This will raise an exception if the channel has previously declared
        # that no more data will be sent (see #eof!).
        #
        #   channel.send_data("the password\n")
        def send_data(data)
          raise EOFError, "cannot send data if channel has declared eof" if eof?
          output.append(data.to_s)
        end
    
        # Returns true if the channel exists in the channel list of the session,
        # and false otherwise. This can be used to determine whether a channel has
        # been closed or not.
        #
        #   ssh.loop { channel.active? }
        def active?
          connection.channels.key?(local_id)
        end
    
        # Runs the SSH event loop until the channel is no longer active. This is
        # handy for blocking while you wait for some channel to finish.
        #
        #   channel.exec("grep ...") { ... }
        #   channel.wait
        def wait
          connection.loop { active? }
        end
    
        # True if close() has been called; NOTE: if the channel has data waiting to
        # be sent then the channel will close after all the data is sent. See
        # closed?() to determine if we have actually sent CHANNEL_CLOSE to server.
        # This may be true for awhile before closed? returns true if we are still
        # sending buffered output to server.
        def closing?
          @closing
        end
    
        # True if we have sent CHANNEL_CLOSE to the remote server.
        def local_closed?
          @local_closed
        end
    
        def remote_closed?
          @remote_closed
        end
    
        def remote_closed!
          @remote_closed = true
        end
    
        # Requests that the channel be closed. It only marks the channel to be closed
        # the CHANNEL_CLOSE message will be sent from event loop
        def close
          return if @closing
          @closing = true
        end
    
        # Returns true if the local end of the channel has declared that no more
        # data is forthcoming (see #eof!). Trying to send data via #send_data when
        # this is true will result in an exception being raised.
        def eof?
          @eof
        end
    
        # Tells the remote end of the channel that no more data is forthcoming
        # from this end of the channel. The remote end may still send data.
        # The CHANNEL_EOF packet will be sent once the output buffer is empty.
        def eof!
          return if eof?
          @eof = true
        end
    
        # If an #on_process handler has been set up, this will cause it to be
        # invoked (passing the channel itself as an argument). It also causes all
        # pending output to be enqueued as CHANNEL_DATA packets (see #enqueue_pending_output).
        def process
          @on_process.call(self) if @on_process
          enqueue_pending_output
    
          if @eof and not @sent_eof and output.empty? and remote_id and not @local_closed
            connection.send_message(Buffer.from(:byte, CHANNEL_EOF, :long, remote_id))
            @sent_eof = true
          end
    
          if @closing and not @local_closed and output.empty? and remote_id
            connection.send_message(Buffer.from(:byte, CHANNEL_CLOSE, :long, remote_id))
            @local_closed = true
            connection.cleanup_channel(self)
          end
        end
    
        # Registers a callback to be invoked when data packets are received by the
        # channel. The callback is called with the channel as the first argument,
        # and the data as the second.
        #
        #   channel.on_data do |ch, data|
        #     puts "got data: #{data.inspect}"
        #   end
        #
        # Data received this way is typically the data written by the remote
        # process to its +stdout+ stream.
        def on_data(&block)
          old, @on_data = @on_data, block
          old
        end
    
        # Registers a callback to be invoked when extended data packets are received
        # by the channel. The callback is called with the channel as the first
        # argument, the data type (as an integer) as the second, and the data as
        # the third. Extended data is almost exclusively used to send +stderr+ data
        # (+type+ == 1). Other extended data types are not defined by the SSH
        # protocol.
        #
        #   channel.on_extended_data do |ch, type, data|
        #     puts "got stderr: #{data.inspect}"
        #   end
        def on_extended_data(&block)
          old, @on_extended_data = @on_extended_data, block
          old
        end
    
        # Registers a callback to be invoked for each pass of the event loop for
        # this channel. There are no guarantees on timeliness in the event loop,
        # but it will be called roughly once for each packet received by the
        # connection (not the channel). This callback is invoked with the channel
        # as the sole argument.
        #
        # Here's an example that accumulates the channel data into a variable on
        # the channel itself, and displays individual lines in the input one
        # at a time when the channel is processed:
        #
        #   channel[:data] = ""
        #
        #   channel.on_data do |ch, data|
        #     channel[:data] << data
        #   end
        #
        #   channel.on_process do |ch|
        #     if channel[:data] =~ /^.*?\n/
        #       puts $&
        #       channel[:data] = $'
        #     end
        #   end
        def on_process(&block)
          old, @on_process = @on_process, block
          old
        end
    
        # Registers a callback to be invoked when the server acknowledges that a
        # channel is closed. This is invoked with the channel as the sole argument.
        #
        #   channel.on_close do |ch|
        #     puts "remote end is closing!"
        #   end
        def on_close(&block)
          old, @on_close = @on_close, block
          old
        end
    
        # Registers a callback to be invoked when the server indicates that no more
        # data will be sent to the channel (although the channel can still send
        # data to the server). The channel is the sole argument to the callback.
        #
        #   channel.on_eof do |ch|
        #     puts "remote end is done sending data"
        #   end
        def on_eof(&block)
          old, @on_eof = @on_eof, block
          old
        end
    
        # Registers a callback to be invoked when the server was unable to open
        # the requested channel. The channel itself will be passed to the block,
        # along with the integer "reason code" for the failure, and a textual
        # description of the failure from the server.
        #
        #   channel = session.open_channel do |ch|
        #     # ..
        #   end
        #
        #   channel.on_open_failed { |ch, code, desc| ... }
        def on_open_failed(&block)
          old, @on_open_failed = @on_open_failed, block
          old
        end
    
        # Registers a callback to be invoked when a channel request of the given
        # type is received. The callback will receive the channel as the first
        # argument, and the associated (unparsed) data as the second. The data
        # will be a Net::SSH::Buffer that you will need to parse, yourself,
        # according to the kind of request you are watching.
        #
        # By default, if the request wants a reply, Net::SSH will send a
        # CHANNEL_SUCCESS response for any request that was handled by a registered
        # callback, and CHANNEL_FAILURE for any that wasn't, but if you want your
        # registered callback to result in a CHANNEL_FAILURE response, just raise
        # Net::SSH::ChannelRequestFailed.
        #
        # Some common channel requests that your programs might want to listen
        # for are:
        #
        # * "exit-status" : the exit status of the remote process will be reported
        #   as a long integer in the data buffer, which you can grab via
        #   data.read_long.
        # * "exit-signal" : if the remote process died as a result of a signal
        #   being sent to it, the signal will be reported as a string in the
        #   data, via data.read_string. (Not all SSH servers support this channel
        #   request type.)
        #
        #     channel.on_request "exit-status" do |ch, data|
        #       puts "process terminated with exit status: #{data.read_long}"
        #     end
        def on_request(type, &block)
          old, @on_request[type] = @on_request[type], block
          old
        end
    
        # Sends a new channel request with the given name. The extra +data+
        # parameter must either be empty, or consist of an even number of
        # arguments. See Net::SSH::Buffer.from for a description of their format.
        # If a block is given, it is registered as a callback for a pending
        # request, and the packet will be flagged so that the server knows a
        # reply is required. If no block is given, the server will send no
        # response to this request. Responses, where required, will cause the
        # callback to be invoked with the channel as the first argument, and
        # either true or false as the second, depending on whether the request
        # succeeded or not. The meaning of "success" and "failure" in this context
        # is dependent on the specific request that was sent.
        #
        #   channel.send_channel_request "shell" do |ch, success|
        #     if success
        #       puts "user shell started successfully"
        #     else
        #       puts "could not start user shell"
        #     end
        #   end
        #
        # Most channel requests you'll want to send are already wrapped in more
        # convenient helper methods (see #exec and #subsystem).
        def send_channel_request(request_name, *data, &callback)
          info { "sending channel request #{request_name.inspect}" }
          fail "Channel open not yet confirmed, please call send_channel_request(or exec) from block of open_channel" unless remote_id
          msg = Buffer.from(:byte, CHANNEL_REQUEST,
            :long, remote_id, :string, request_name,
            :bool, !callback.nil?, *data)
          connection.send_message(msg)
          pending_requests << callback if callback
        end
    
        public # these methods are public, but for Net::SSH internal use only
    
        # Enqueues pending output at the connection as CHANNEL_DATA packets. This
        # does nothing if the channel has not yet been confirmed open (see
        # #do_open_confirmation). This is called automatically by #process, which
        # is called from the event loop (Connection::Session#process). You will
        # generally not need to invoke it directly.
        def enqueue_pending_output #:nodoc:
          return unless remote_id
    
          while output.length > 0
            length = output.length
            length = remote_window_size if length > remote_window_size
            length = remote_maximum_packet_size if length > remote_maximum_packet_size
    
            if length > 0
              connection.send_message(Buffer.from(:byte, CHANNEL_DATA, :long, remote_id, :string, output.read(length)))
              output.consume!
              @remote_window_size -= length
            else
              break
            end
          end
        end
    
        # Invoked when the server confirms that a channel has been opened.
        # The remote_id is the id of the channel as assigned by the remote host,
        # and max_window and max_packet are the maximum window and maximum
        # packet sizes, respectively. If an open-confirmation callback was
        # given when the channel was created, it is invoked at this time with
        # the channel itself as the sole argument.
        def do_open_confirmation(remote_id, max_window, max_packet) #:nodoc:
          @remote_id = remote_id
          @remote_window_size = @remote_maximum_window_size = max_window
          @remote_maximum_packet_size = max_packet
          connection.forward.agent(self) if connection.options[:forward_agent] && type == "session"
          forward_local_env(connection.options[:send_env]) if connection.options[:send_env]
          @on_confirm_open.call(self) if @on_confirm_open
        end
    
        # Invoked when the server failed to open the channel. If an #on_open_failed
        # callback was specified, it will be invoked with the channel, reason code,
        # and description as arguments. Otherwise, a ChannelOpenFailed exception
        # will be raised.
        def do_open_failed(reason_code, description)
          if @on_open_failed
            @on_open_failed.call(self, reason_code, description)
          else
            raise ChannelOpenFailed.new(reason_code, description)
          end
        end
    
        # Invoked when the server sends a CHANNEL_WINDOW_ADJUST packet, and
        # causes the remote window size to be adjusted upwards by the given
        # number of bytes. This has the effect of allowing more data to be sent
        # from the local end to the remote end of the channel.
        def do_window_adjust(bytes) #:nodoc:
          @remote_maximum_window_size += bytes
          @remote_window_size += bytes
        end
    
        # Invoked when the server sends a channel request. If any #on_request
        # callback has been registered for the specific type of this request,
        # it is invoked. If +want_reply+ is true, a packet will be sent of
        # either CHANNEL_SUCCESS or CHANNEL_FAILURE type. If there was no callback
        # to handle the request, CHANNEL_FAILURE will be sent. Otherwise,
        # CHANNEL_SUCCESS, unless the callback raised ChannelRequestFailed. The
        # callback should accept the channel as the first argument, and the
        # request-specific data as the second.
        def do_request(request, want_reply, data) #:nodoc:
          result = true
    
          begin
            callback = @on_request[request] or raise ChannelRequestFailed
            callback.call(self, data)
          rescue ChannelRequestFailed
            result = false
          end
    
          if want_reply
            msg = Buffer.from(:byte, result ? CHANNEL_SUCCESS : CHANNEL_FAILURE, :long, remote_id)
            connection.send_message(msg)
          end
        end
    
        # Invokes the #on_data callback when the server sends data to the
        # channel. This will reduce the available window size on the local end,
        # but does not actually throttle requests that come in illegally when
        # the window size is too small. The callback is invoked with the channel
        # as the first argument, and the data as the second.
        def do_data(data) #:nodoc:
          update_local_window_size(data.length)
          @on_data.call(self, data) if @on_data
        end
    
        # Invokes the #on_extended_data callback when the server sends
        # extended data to the channel. This will reduce the available window
        # size on the local end. The callback is invoked with the channel,
        # type, and data.
        def do_extended_data(type, data)
          update_local_window_size(data.length)
          @on_extended_data.call(self, type, data) if @on_extended_data
        end
    
        # Invokes the #on_eof callback when the server indicates that no
        # further data is forthcoming. The callback is invoked with the channel
        # as the argument.
        def do_eof
          @on_eof.call(self) if @on_eof
        end
    
        # Invokes the #on_close callback when the server closes a channel.
        # The channel is the only argument.
        def do_close
          @on_close.call(self) if @on_close
        end
    
        # Invokes the next pending request callback with +false+ as the second
        # argument.
        def do_failure
          if callback = pending_requests.shift
            callback.call(self, false)
          else
            error { "channel failure received with no pending request to handle it (bug?)" }
          end
        end
    
        # Invokes the next pending request callback with +true+ as the second
        # argument.
        def do_success
          if callback = pending_requests.shift
            callback.call(self, true)
          else
            error { "channel success received with no pending request to handle it (bug?)" }
          end
        end

        private

        # Runs the SSH event loop until the remote confirmed channel open
        # experimental api
        def wait_until_open_confirmed
          connection.loop { !remote_id }
        end

        LOCAL_WINDOW_SIZE_INCREMENT = 0x20000
        GOOD_LOCAL_MAXIUMUM_WINDOW_SIZE = 10 * LOCAL_WINDOW_SIZE_INCREMENT

        # Updates the local window size by the given amount. If the window
        # size drops to less than half of the local maximum (an arbitrary
        # threshold), a CHANNEL_WINDOW_ADJUST message will be sent to the
        # server telling it that the window size has grown.
        def update_local_window_size(size)
          @local_window_size -= size
          if local_window_size < local_maximum_window_size / 2
            connection.send_message(Buffer.from(:byte, CHANNEL_WINDOW_ADJUST,
              :long, remote_id, :long, LOCAL_WINDOW_SIZE_INCREMENT))
            @local_window_size += LOCAL_WINDOW_SIZE_INCREMENT
            @local_maximum_window_size += LOCAL_WINDOW_SIZE_INCREMENT if @local_maximum_window_size < @local_window_size || @local_maximum_window_size < GOOD_LOCAL_MAXIUMUM_WINDOW_SIZE
          end
        end

        # Gets an +Array+ of local environment variables in the remote process'
        # environment.
        # A variable name can either be described by a +Regexp+ or +String+.
        #
        #   channel.forward_local_env [/^GIT_.*$/, "LANG"]
        def forward_local_env(env_variable_patterns)
          Array(env_variable_patterns).each do |env_variable_pattern|
            matched_variables = ENV.find_all do |env_name, _|
              case env_variable_pattern
              when Regexp then env_name =~ env_variable_pattern
              when String then env_name == env_variable_pattern
              end
            end
            matched_variables.each do |env_name, env_value|
              self.env(env_name, env_value)
            end
          end
        end
      end

    end
  end
end
