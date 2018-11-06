require 'net/ssh/loggable'
require 'net/ssh/ruby_compat'
require 'net/ssh/connection/channel'
require 'net/ssh/connection/constants'
require 'net/ssh/service/forward'
require 'net/ssh/connection/keepalive'
require 'net/ssh/connection/event_loop'

module Net 
  module SSH 
    module Connection

      # A session class representing the connection service running on top of
      # the SSH transport layer. It manages the creation of channels (see
      # #open_channel), and the dispatching of messages to the various channels.
      # It also encapsulates the SSH event loop (via #loop and #process),
      # and serves as a central point-of-reference for all SSH-related services (e.g.
      # port forwarding, SFTP, SCP, etc.).
      #
      # You will rarely (if ever) need to instantiate this class directly; rather,
      # you'll almost always use Net::SSH.start to initialize a new network
      # connection, authenticate a user, and return a new connection session,
      # all in one call.
      #
      #   Net::SSH.start("localhost", "user") do |ssh|
      #     # 'ssh' is an instance of Net::SSH::Connection::Session
      #     ssh.exec! "/etc/init.d/some_process start"
      #   end
      class Session
        include Loggable
        include Constants
    
        # Default IO.select timeout threshold
        DEFAULT_IO_SELECT_TIMEOUT = 300
    
        # The underlying transport layer abstraction (see Net::SSH::Transport::Session).
        attr_reader :transport
    
        # The map of options that were used to initialize this instance.
        attr_reader :options
    
        # The collection of custom properties for this instance. (See #[] and #[]=).
        attr_reader :properties
    
        # The map of channels, each key being the local-id for the channel.
        attr_reader :channels #:nodoc:
    
        # The map of listeners that the event loop knows about. See #listen_to.
        attr_reader :listeners #:nodoc:
    
        # The map of specialized handlers for opening specific channel types. See
        # #on_open_channel.
        attr_reader :channel_open_handlers #:nodoc:
    
        # The list of callbacks for pending requests. See #send_global_request.
        attr_reader :pending_requests #:nodoc:
    
        class NilChannel
          def initialize(session)
            @session = session
          end
    
          def method_missing(sym, *args)
            @session.lwarn { "ignoring request #{sym.inspect} for non-existent (closed?) channel; probably ssh server bug" }
          end
        end
    
        # Create a new connection service instance atop the given transport
        # layer. Initializes the listeners to be only the underlying socket object.
        def initialize(transport, options={})
          self.logger = transport.logger
    
          @transport = transport
          @options = options
    
          @channel_id_counter = -1
          @channels = Hash.new(NilChannel.new(self))
          @listeners = { transport.socket => nil }
          @pending_requests = []
          @channel_open_handlers = {}
          @on_global_request = {}
          @properties = (options[:properties] || {}).dup
    
          @max_pkt_size = (options.key?(:max_pkt_size) ? options[:max_pkt_size] : 0x8000)
          @max_win_size = (options.key?(:max_win_size) ? options[:max_win_size] : 0x20000)
    
          @keepalive = Keepalive.new(self)
    
          @event_loop = options[:event_loop] || SingleSessionEventLoop.new
          @event_loop.register(self)
        end
    
        # Retrieves a custom property from this instance. This can be used to
        # store additional state in applications that must manage multiple
        # SSH connections.
        def [](key)
          @properties[key]
        end
    
        # Sets a custom property for this instance.
        def []=(key, value)
          @properties[key] = value
        end
    
        # Returns the name of the host that was given to the transport layer to
        # connect to.
        def host
          transport.host
        end
    
        # Returns true if the underlying transport has been closed. Note that
        # this can be a little misleading, since if the remote server has
        # closed the connection, the local end will still think it is open
        # until the next operation on the socket. Nevertheless, this method can
        # be useful if you just want to know if _you_ have closed the connection.
        def closed?
          transport.closed?
        end
    
        # Closes the session gracefully, blocking until all channels have
        # successfully closed, and then closes the underlying transport layer
        # connection.
        def close
          info { "closing remaining channels (#{channels.length} open)" }
          channels.each { |id, channel| channel.close }
          begin
            loop(0.1) { channels.any? }
          rescue Net::SSH::Disconnect
            raise unless channels.empty?
          end
          transport.close
        end
    
        # Performs a "hard" shutdown of the connection. In general, this should
        # never be done, but it might be necessary (in a rescue clause, for instance,
        # when the connection needs to close but you don't know the status of the
        # underlying protocol's state).
        def shutdown!
          transport.shutdown!
        end
    
        # preserve a reference to Kernel#loop
        alias :loop_forever :loop
    
        # Returns +true+ if there are any channels currently active on this
        # session. By default, this will not include "invisible" channels
        # (such as those created by forwarding ports and such), but if you pass
        # a +true+ value for +include_invisible+, then those will be counted.
        #
        # This can be useful for determining whether the event loop should continue
        # to be run.
        #
        #   ssh.loop { ssh.busy? }
        def busy?(include_invisible=false)
          if include_invisible
            channels.any?
          else
            channels.any? { |id, ch| !ch[:invisible] }
          end
        end
    
        # The main event loop. Calls #process until #process returns false. If a
        # block is given, it is passed to #process, otherwise a default proc is
        # used that just returns true if there are any channels active (see #busy?).
        # The # +wait+ parameter is also passed through to #process (where it is
        # interpreted as the maximum number of seconds to wait for IO.select to return).
        #
        #   # loop for as long as there are any channels active
        #   ssh.loop
        #
        #   # loop for as long as there are any channels active, but make sure
        #   # the event loop runs at least once per 0.1 second
        #   ssh.loop(0.1)
        #
        #   # loop until ctrl-C is pressed
        #   int_pressed = false
        #   trap("INT") { int_pressed = true }
        #   ssh.loop(0.1) { not int_pressed }
        def loop(wait=nil, &block)
          running = block || Proc.new { busy? }
          loop_forever { break unless process(wait, &running) }
          begin
            process(0)
          rescue IOError => e
            if e.message =~ /closed/
              debug { "stream was closed after loop => shallowing exception so it will be re-raised in next loop" }
            else
              raise
            end
          end
        end
    
        # The core of the event loop. It processes a single iteration of the event
        # loop. If a block is given, it should return false when the processing
        # should abort, which causes #process to return false. Otherwise,
        # #process returns true. The session itself is yielded to the block as its
        # only argument.
        #
        # If +wait+ is nil (the default), this method will block until any of the
        # monitored IO objects are ready to be read from or written to. If you want
        # it to not block, you can pass 0, or you can pass any other numeric value
        # to indicate that it should block for no more than that many seconds.
        # Passing 0 is a good way to poll the connection, but if you do it too
        # frequently it can make your CPU quite busy!
        #
        # This will also cause all active channels to be processed once each (see
        # Net::SSH::Connection::Channel#on_process).
        #
        # TODO revise example
        #
        #   # process multiple Net::SSH connections in parallel
        #   connections = [
        #     Net::SSH.start("host1", ...),
        #     Net::SSH.start("host2", ...)
        #   ]
        #
        #   connections.each do |ssh|
        #     ssh.exec "grep something /in/some/files"
        #   end
        #
        #   condition = Proc.new { |s| s.busy? }
        #
        #   loop do
        #     connections.delete_if { |ssh| !ssh.process(0.1, &condition) }
        #     break if connections.empty?
        #   end
        def process(wait=nil, &block)
          @event_loop.process(wait, &block)
        rescue StandardError
          force_channel_cleanup_on_close if closed?
          raise
        end
    
        # This is called internally as part of #process. It dispatches any
        # available incoming packets, and then runs Net::SSH::Connection::Channel#process
        # for any active channels. If a block is given, it is invoked at the
        # start of the method and again at the end, and if the block ever returns
        # false, this method returns false. Otherwise, it returns true.
        def preprocess(&block)
          return false if block_given? && !yield(self)
          ev_preprocess(&block)
          return false if block_given? && !yield(self)
          return true
        end
    
        # Called by event loop to process available data before going to
        # event multiplexing
        def ev_preprocess(&block)
          dispatch_incoming_packets(raise_disconnect_errors: false)
          each_channel { |id, channel| channel.process unless channel.local_closed? }
        end
    
        # Returns the file descriptors the event loop should wait for read/write events,
        # we also return the max wait
        def ev_do_calculate_rw_wait(wait)
          r = listeners.keys
          w = r.select { |w2| w2.respond_to?(:pending_write?) && w2.pending_write? }
          [r,w,io_select_wait(wait)]
        end
    
        # This is called internally as part of #process.
        def postprocess(readers, writers)
          ev_do_handle_events(readers, writers)
        end
    
        # It loops over the given arrays of reader IO's and writer IO's,
        # processing them as needed, and
        # then calls Net::SSH::Transport::Session#rekey_as_needed to allow the
        # transport layer to rekey. Then returns true.
        def ev_do_handle_events(readers, writers)
          Array(readers).each do |reader|
            if listeners[reader]
              listeners[reader].call(reader)
            else
              if reader.fill.zero?
                reader.close
                stop_listening_to(reader)
              end
            end
          end
    
          Array(writers).each do |writer|
            writer.send_pending
          end
        end
    
        # calls Net::SSH::Transport::Session#rekey_as_needed to allow the
        # transport layer to rekey
        def ev_do_postprocess(was_events)
          @keepalive.send_as_needed(was_events)
          transport.rekey_as_needed
          true
        end
    
        # Send a global request of the given type. The +extra+ parameters must
        # be even in number, and conform to the same format as described for
        # Net::SSH::Buffer.from. If a callback is not specified, the request will
        # not require a response from the server, otherwise the server is required
        # to respond and indicate whether the request was successful or not. This
        # success or failure is indicated by the callback being invoked, with the
        # first parameter being true or false (success, or failure), and the second
        # being the packet itself.
        #
        # Generally, Net::SSH will manage global requests that need to be sent
        # (e.g. port forward requests and such are handled in the Net::SSH::Service::Forward
        # class, for instance). However, there may be times when you need to
        # send a global request that isn't explicitly handled by Net::SSH, and so
        # this method is available to you.
        #
        #   ssh.send_global_request("keep-alive@openssh.com")
        def send_global_request(type, *extra, &callback)
          info { "sending global request #{type}" }
          msg = Buffer.from(:byte, GLOBAL_REQUEST, :string, type.to_s, :bool, !callback.nil?, *extra)
          send_message(msg)
          pending_requests << callback if callback
          self
        end
    
        # Requests that a new channel be opened. By default, the channel will be
        # of type "session", but if you know what you're doing you can select any
        # of the channel types supported by the SSH protocol. The +extra+ parameters
        # must be even in number and conform to the same format as described for
        # Net::SSH::Buffer.from. If a callback is given, it will be invoked when
        # the server confirms that the channel opened successfully. The sole parameter
        # for the callback is the channel object itself.
        #
        # In general, you'll use #open_channel without any arguments; the only
        # time you'd want to set the channel type or pass additional initialization
        # data is if you were implementing an SSH extension.
        #
        #   channel = ssh.open_channel do |ch|
        #     ch.exec "grep something /some/files" do |ch, success|
        #       ...
        #     end
        #   end
        #
        #   channel.wait
        def open_channel(type="session", *extra, &on_confirm)
          local_id = get_next_channel_id
    
          channel = Channel.new(self, type, local_id, @max_pkt_size, @max_win_size, &on_confirm)
          msg = Buffer.from(:byte, CHANNEL_OPEN, :string, type, :long, local_id,
            :long, channel.local_maximum_window_size,
            :long, channel.local_maximum_packet_size, *extra)
          send_message(msg)
    
          channels[local_id] = channel
        end
    
        class StringWithExitstatus < String
          def initialize(str, exitstatus)
            super(str)
            @exitstatus = exitstatus
          end
    
          attr_reader :exitstatus
        end
    
        # A convenience method for executing a command and interacting with it. If
        # no block is given, all output is printed via $stdout and $stderr. Otherwise,
        # the block is called for each data and extended data packet, with three
        # arguments: the channel object, a symbol indicating the data type
        # (:stdout or :stderr), and the data (as a string).
        #
        # Note that this method returns immediately, and requires an event loop
        # (see Session#loop) in order for the command to actually execute.
        #
        # This is effectively identical to calling #open_channel, and then
        # Net::SSH::Connection::Channel#exec, and then setting up the channel
        # callbacks. However, for most uses, this will be sufficient.
        #
        #   ssh.exec "grep something /some/files" do |ch, stream, data|
        #     if stream == :stderr
        #       puts "ERROR: #{data}"
        #     else
        #       puts data
        #     end
        #   end
        def exec(command, status: nil, &block)
          open_channel do |channel|
            channel.exec(command) do |ch, success|
              raise "could not execute command: #{command.inspect}" unless success
    
              if status
                channel.on_request("exit-status") do |ch2,data|
                  status[:exit_code] = data.read_long
                end
    
                channel.on_request("exit-signal") do |ch2, data|
                  status[:exit_signal] = data.read_long
                end
              end
    
              channel.on_data do |ch2, data|
                if block
                  block.call(ch2, :stdout, data)
                else
                  $stdout.print(data)
                end
              end
    
              channel.on_extended_data do |ch2, type, data|
                if block
                  block.call(ch2, :stderr, data)
                else
                  $stderr.print(data)
                end
              end
            end
          end
        end
    
        # Same as #exec, except this will block until the command finishes. Also,
        # if no block is given, this will return all output (stdout and stderr)
        # as a single string.
        #
        #   matches = ssh.exec!("grep something /some/files")
        #
        # the returned string has an exitstatus method to query it's exit satus
        def exec!(command, status: nil, &block)
          block_or_concat = block || Proc.new do |ch, type, data|
            ch[:result] ||= ""
            ch[:result] << data
          end
    
          status ||= {}
          channel = exec(command, status: status, &block_or_concat)
          channel.wait
    
          channel[:result] ||= "" unless block
          channel[:result] &&= channel[:result].force_encoding("UTF-8") unless block
    
          StringWithExitstatus.new(channel[:result], status[:exit_code]) if channel[:result]
        end
    
        # Enqueues a message to be sent to the server as soon as the socket is
        # available for writing. Most programs will never need to call this, but
        # if you are implementing an extension to the SSH protocol, or if you
        # need to send a packet that Net::SSH does not directly support, you can
        # use this to send it.
        #
        #  ssh.send_message(Buffer.from(:byte, REQUEST_SUCCESS).to_s)
        def send_message(message)
          transport.enqueue_message(message)
        end
    
        # Adds an IO object for the event loop to listen to. If a callback
        # is given, it will be invoked when the io is ready to be read, otherwise,
        # the io will merely have its #fill method invoked.
        #
        # Any +io+ value passed to this method _must_ have mixed into it the
        # Net::SSH::BufferedIo functionality, typically by calling #extend on the
        # object.
        #
        # The following example executes a process on the remote server, opens
        # a socket to somewhere, and then pipes data from that socket to the
        # remote process' stdin stream:
        #
        #   channel = ssh.open_channel do |ch|
        #     ch.exec "/some/process/that/wants/input" do |ch, success|
        #       abort "can't execute!" unless success
        #
        #       io = TCPSocket.new(somewhere, port)
        #       io.extend(Net::SSH::BufferedIo)
        #       ssh.listen_to(io)
        #
        #       ch.on_process do
        #         if io.available > 0
        #           ch.send_data(io.read_available)
        #         end
        #       end
        #
        #       ch.on_close do
        #         ssh.stop_listening_to(io)
        #         io.close
        #       end
        #     end
        #   end
        #
        #   channel.wait
        def listen_to(io, &callback)
          listeners[io] = callback
        end
    
        # Removes the given io object from the listeners collection, so that the
        # event loop will no longer monitor it.
        def stop_listening_to(io)
          listeners.delete(io)
        end
    
        # Returns a reference to the Net::SSH::Service::Forward service, which can
        # be used for forwarding ports over SSH.
        def forward
          @forward ||= Service::Forward.new(self)
        end
    
        # Registers a handler to be invoked when the server wants to open a
        # channel on the client. The callback receives the connection object,
        # the new channel object, and the packet itself as arguments, and should
        # raise ChannelOpenFailed if it is unable to open the channel for some
        # reason. Otherwise, the channel will be opened and a confirmation message
        # sent to the server.
        #
        # This is used by the Net::SSH::Service::Forward service to open a channel
        # when a remote forwarded port receives a connection. However, you are
        # welcome to register handlers for other channel types, as needed.
        def on_open_channel(type, &block)
          channel_open_handlers[type] = block
        end
    
        # Registers a handler to be invoked when the server sends a global request
        # of the given type. The callback receives the request data as the first
        # parameter, and true/false as the second (indicating whether a response
        # is required). If the callback sends the response, it should return
        # :sent. Otherwise, if it returns true, REQUEST_SUCCESS will be sent, and
        # if it returns false, REQUEST_FAILURE will be sent.
        def on_global_request(type, &block)
          old, @on_global_request[type] = @on_global_request[type], block
          old
        end
    
        def cleanup_channel(channel)
          if channel.local_closed? and channel.remote_closed?
            info { "#{host} delete channel #{channel.local_id} which closed locally and remotely" }
            channels.delete(channel.local_id)
          end
        end
    
        # If the #preprocess and #postprocess callbacks for this session need to run
        # periodically, this method returns the maximum number of seconds which may
        # pass between callbacks.
        def max_select_wait_time
          @keepalive.interval if @keepalive.enabled?
        end
    
        private
    
        # iterate channels with the posibility of callbacks opening new channels during the iteration
        def each_channel(&block)
          channels.dup.each(&block)
        end
    
        # Read all pending packets from the connection and dispatch them as
        # appropriate. Returns as soon as there are no more pending packets.
        def dispatch_incoming_packets(raise_disconnect_errors: true)
          while packet = transport.poll_message
            raise Net::SSH::Exception, "unexpected response #{packet.type} (#{packet.inspect})" unless MAP.key?(packet.type)
    
            send(MAP[packet.type], packet)
          end
        rescue StandardError
          force_channel_cleanup_on_close if closed?
          raise if raise_disconnect_errors || !$!.is_a?(Net::SSH::Disconnect)
        end
    
        # Returns the next available channel id to be assigned, and increments
        # the counter.
        def get_next_channel_id
          @channel_id_counter += 1
        end
    
        def force_channel_cleanup_on_close
          channels.each do |id, channel|
            channel_closed(channel)
          end
        end
    
        def channel_closed(channel)
          channel.remote_closed!
          channel.close
    
          cleanup_channel(channel)
          channel.do_close
        end
    
        # Invoked when a global request is received. The registered global
        # request callback will be invoked, if one exists, and the necessary
        # reply returned.
        def global_request(packet)
          info { "global request received: #{packet[:request_type]} #{packet[:want_reply]}" }
          callback = @on_global_request[packet[:request_type]]
          result = callback ? callback.call(packet[:request_data], packet[:want_reply]) : false
    
          raise "expected global request handler for `#{packet[:request_type]}' to return true, false, or :sent, but got #{result.inspect}" if result != :sent && result != true && result != false
    
          if packet[:want_reply] && result != :sent
            msg = Buffer.from(:byte, result ? REQUEST_SUCCESS : REQUEST_FAILURE)
            send_message(msg)
          end
        end
    
        # Invokes the next pending request callback with +true+.
        def request_success(packet)
          info { "global request success" }
          callback = pending_requests.shift
          callback.call(true, packet) if callback
        end
    
        # Invokes the next pending request callback with +false+.
        def request_failure(packet)
          info { "global request failure" }
          callback = pending_requests.shift
          callback.call(false, packet) if callback
        end
    
        # Called when the server wants to open a channel. If no registered
        # channel handler exists for the given channel type, CHANNEL_OPEN_FAILURE
        # is returned, otherwise the callback is invoked and everything proceeds
        # accordingly.
        def channel_open(packet)
          info { "channel open #{packet[:channel_type]}" }
    
          local_id = get_next_channel_id
    
          channel = Channel.new(self, packet[:channel_type], local_id, @max_pkt_size, @max_win_size)
          channel.do_open_confirmation(packet[:remote_id], packet[:window_size], packet[:packet_size])
    
          callback = channel_open_handlers[packet[:channel_type]]
    
          if callback
            begin
              callback[self, channel, packet]
            rescue ChannelOpenFailed => err
              failure = [err.code, err.reason]
            else
              channels[local_id] = channel
              msg = Buffer.from(:byte, CHANNEL_OPEN_CONFIRMATION, :long, channel.remote_id, :long, channel.local_id, :long, channel.local_maximum_window_size, :long, channel.local_maximum_packet_size)
            end
          else
            failure = [3, "unknown channel type #{channel.type}"]
          end
    
          if failure
            error { failure.inspect }
            msg = Buffer.from(:byte, CHANNEL_OPEN_FAILURE, :long, channel.remote_id, :long, failure[0], :string, failure[1], :string, "")
          end
    
          send_message(msg)
        end
    
        def channel_open_confirmation(packet)
          info { "channel_open_confirmation: #{packet[:local_id]} #{packet[:remote_id]} #{packet[:window_size]} #{packet[:packet_size]}" }
          channel = channels[packet[:local_id]]
          channel.do_open_confirmation(packet[:remote_id], packet[:window_size], packet[:packet_size])
        end
    
        def channel_open_failure(packet)
          error { "channel_open_failed: #{packet[:local_id]} #{packet[:reason_code]} #{packet[:description]}" }
          channel = channels.delete(packet[:local_id])
          channel.do_open_failed(packet[:reason_code], packet[:description])
        end
    
        def channel_window_adjust(packet)
          info { "channel_window_adjust: #{packet[:local_id]} +#{packet[:extra_bytes]}" }
          channels[packet[:local_id]].do_window_adjust(packet[:extra_bytes])
        end
    
        def channel_request(packet)
          info { "channel_request: #{packet[:local_id]} #{packet[:request]} #{packet[:want_reply]}" }
          channels[packet[:local_id]].do_request(packet[:request], packet[:want_reply], packet[:request_data])
        end
    
        def channel_data(packet)
          info { "channel_data: #{packet[:local_id]} #{packet[:data].length}b" }
          channels[packet[:local_id]].do_data(packet[:data])
        end
    
        def channel_extended_data(packet)
          info { "channel_extended_data: #{packet[:local_id]} #{packet[:data_type]} #{packet[:data].length}b" }
          channels[packet[:local_id]].do_extended_data(packet[:data_type], packet[:data])
        end
    
        def channel_eof(packet)
          info { "channel_eof: #{packet[:local_id]}" }
          channels[packet[:local_id]].do_eof
        end
    
        def channel_close(packet)
          info { "channel_close: #{packet[:local_id]}" }
    
          channel = channels[packet[:local_id]]
          channel_closed(channel)
        end
    
        def channel_success(packet)
          info { "channel_success: #{packet[:local_id]}" }
          channels[packet[:local_id]].do_success
        end
    
        def channel_failure(packet)
          info { "channel_failure: #{packet[:local_id]}" }
          channels[packet[:local_id]].do_failure
        end
    
        def io_select_wait(wait)
          [wait, max_select_wait_time].compact.min
        end
    
        MAP = Constants.constants.each_with_object({}) do |name, memo|
          value = const_get(name)
          next unless Integer === value
          memo[value] = name.downcase.to_sym
        end
      end

    end
  end
end
