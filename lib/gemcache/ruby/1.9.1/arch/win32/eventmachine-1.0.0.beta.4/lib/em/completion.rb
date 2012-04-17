# = EM::Completion
#
# A completion is a callback container for various states of completion. In
# it's most basic form it has a start state and a finish state.
#
# This implementation includes some hold-back from the EM::Deferrable
# interface in order to be compatible - but it has a much cleaner
# implementation.
#
# In general it is preferred that this implementation be used as a state
# callback container than EM::DefaultDeferrable or other classes including
# EM::Deferrable. This is because it is generally more sane to keep this level
# of state in a dedicated state-back container. This generally leads to more
# malleable interfaces and software designs, as well as eradicating nasty bugs
# that result from abstraction leakage.
#
# == Basic Usage
#
# As already mentioned, the basic usage of a Completion is simply for its two
# final states, :succeeded and :failed.
#
# An asynchronous operation will complete at some future point in time, and
# users often want to react to this event. API authors will want to expose
# some common interface to react to these events.
#
# In the following example, the user wants to know when a short lived
# connection has completed its exchange with the remote server. The simple
# protocol just waits for an ack to its message.
#
#    class Protocol < EM::Connection
#      include EM::P::LineText2
#
#      def initialize(message, completion)
#        @message, @completion = message, completion
#        @completion.completion { close_connection }
#        @completion.timeout(1, :timeout)
#      end
#
#      def post_init
#        send_data(@message)
#      end
#
#      def receive_line(line)
#        case line
#        when /ACK/i
#          @completion.succeed line
#        when /ERR/i
#          @completion.fail :error, line
#        else
#          @completion.fail :unknown, line
#        end
#      end
#  
#      def unbind
#        @completion.fail :disconnected unless @completion.completed?
#      end
#    end
#
#    class API
#      attr_reader :host, :port
#
#      def initialize(host = 'example.org', port = 8000)
#        @host, @port = host, port
#      end
#
#      def request(message)
#        completion = EM::Deferrable::Completion.new
#        EM.connect(host, port, Protocol, message, completion)
#        completion
#      end
#    end
#
#    api = API.new
#    completion = api.request('stuff')
#    completion.callback do |line|
#      puts "API responded with: #{line}"
#    end
#    completion.errback do |type, line|
#      case type
#      when :error
#        puts "API error: #{line}"
#      when :unknown
#        puts "API returned unknown response: #{line}"
#      when :disconnected
#        puts "API server disconnected prematurely"
#      when :timeout
#        puts "API server did not respond in a timely fashion"
#      end
#    end
#
# == Advanced Usage
#
# This completion implementation also supports more state callbacks and
# arbitrary states (unlike the original Deferrable API). This allows for basic
# stateful process encapsulation. One might use this to setup state callbacks
# for various states in an exchange like in the basic usage example, except
# where the applicaiton could be made to react to "connected" and
# "disconnected" states additionally.
#
#    class Protocol < EM::Connection
#      def initialize(completion)
#        @response = []
#        @completion = completion
#        @completion.stateback(:disconnected) do
#          @completion.succeed @response.join
#        end
#      end
#
#      def connection_completed
#        @host, @port = Socket.unpack_sockaddr_in get_peername
#        @completion.change_state(:connected, @host, @port)
#        send_data("GET http://example.org/ HTTP/1.0\r\n\r\n")
#      end
#
#      def receive_data(data)
#        @response << data
#      end
#
#      def unbind
#        @completion.change_state(:disconnected, @host, @port)
#      end
#    end
#
#    completion = EM::Deferrable::Completion.new
#    completion.stateback(:connected) do |host, port|
#      puts "Connected to #{host}:#{port}"
#    end
#    completion.stateback(:disconnected) do |host, port|
#      puts "Disconnected from #{host}:#{port}"
#    end
#    completion.callback do |response|
#      puts response
#    end
#
#    EM.connect('example.org', 80, Protocol, completion)
#
# == Timeout
#
# The Completion also has a timeout. The timeout is global and is not aware of
# states apart from completion states. The timeout is only engaged if #timeout
# is called, and it will call fail if it is reached.
#
# == Completion states
#
# By default there are two completion states, :succeeded and :failed. These
# states can be modified by subclassing and overrding the #completion_states
# method. Completion states are special, in that callbacks for all completion
# states are explcitly cleared when a completion state is entered. This
# prevents errors that could arise from accidental unterminated timeouts, and
# other such user errors.
#
# == Other notes
#
# Several APIs have been carried over from EM::Deferrable for compatibility
# reasons during a transitionary period. Specifically cancel_errback and
# cancel_callback are implemented, but their usage is to be strongly
# discouraged. Due to the already complex nature of reaction systems, dynamic
# callback deletion only makes the problem much worse. It is always better to
# add correct conditionals to the callback code, or use more states, than to
# address such implementaiton issues with conditional callbacks.

module EventMachine

  class Completion
    # This is totally not used (re-implemented), it's here in case people check
    # for kind_of?
    include EventMachine::Deferrable

    attr_reader :state, :value

    def initialize
      @state = :unknown
      @callbacks = Hash.new { |h,k| h[k] = [] }
      @value = []
      @timeout_timer = nil
    end

    # Enter the :succeeded state, setting the result value if given.
    def succeed(*args)
      change_state(:succeeded, *args)
    end
    # The old EM method:
    alias set_deferred_success succeed

    # Enter the :failed state, setting the result value if given.
    def fail(*args)
      change_state(:failed, *args)
    end
    # The old EM method:
    alias set_deferred_failure fail

    # Statebacks are called when you enter (or are in) the named state.
    def stateback(state, *a, &b)
      # The following is quite unfortunate special casing for :completed
      # statebacks, but it's a necessary evil for latent completion
      # definitions.

      if :completed == state || !completed? || @state == state
        @callbacks[state] << EM::Callback(*a, &b)
      end
      execute_callbacks
      self
    end

    # Callbacks are called when you enter (or are in) a :succeeded state.
    def callback(*a, &b)
      stateback(:succeeded, *a, &b)
    end

    # Errbacks are called when you enter (or are in) a :failed state.
    def errback(*a, &b)
      stateback(:failed, *a, &b)
    end

    # Completions are called when you enter (or are in) either a :failed or a
    # :succeeded state. They are stored as a special (reserved) state called
    # :completed.
    def completion(*a, &b)
      stateback(:completed, *a, &b)
    end

    # Enter a new state, setting the result value if given. If the state is one
    # of :succeeded or :failed, then :completed callbacks will also be called.
    def change_state(state, *args)
      @value = args
      @state = state

      EM.schedule { execute_callbacks }
    end

    # The old EM method:
    alias set_deferred_status change_state

    # Indicates that we've reached some kind of completion state, by default
    # this is :succeeded or :failed. Due to these semantics, the :completed
    # state is reserved for internal use.
    def completed?
      completion_states.any? { |s| state == s }
    end

    # Completion states simply returns a list of completion states, by default
    # this is :succeeded and :failed.
    def completion_states
      [:succeeded, :failed]
    end

    # Schedule a time which if passes before we enter a completion state, this
    # deferrable will be failed with the given arguments.
    def timeout(time, *args)
      cancel_timeout
      @timeout_timer = EM::Timer.new(time) do
        fail(*args) unless completed?
      end
    end

    # Disable the timeout
    def cancel_timeout
      if @timeout_timer
        @timeout_timer.cancel
        @timeout_timer = nil
      end
    end

    # Remove an errback. N.B. Some errbacks cannot be deleted. Usage is NOT
    # recommended, this is an anti-pattern.
    def cancel_errback(*a, &b)
      @callbacks[:failed].delete(EM::Callback(*a, &b))
    end

    # Remove a callback. N.B. Some callbacks cannot be deleted. Usage is NOT
    # recommended, this is an anti-pattern.
    def cancel_callback(*a, &b)
      @callbacks[:succeeded].delete(EM::Callback(*a, &b))
    end

    private
    # Execute all callbacks for the current state. If in a completed state, then
    # call any statebacks associated with the completed state.
    def execute_callbacks
      execute_state_callbacks(state)
      if completed?
        execute_state_callbacks(:completed)
        clear_dead_callbacks
        cancel_timeout
      end
    end

    # Iterate all callbacks for a given state, and remove then call them.
    def execute_state_callbacks(state)
      while callback = @callbacks[state].shift
        callback.call(*value)
      end
    end

    # If we enter a completion state, clear other completion states after all
    # callback chains are completed. This means that operation specific
    # callbacks can't be dual-called, which is most common user error.
    def clear_dead_callbacks
      completion_states.each do |state|
        @callbacks[state].clear
      end
    end
  end
end
