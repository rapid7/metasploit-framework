# -*- coding: binary -*-
# frozen_string_literal: true

module Msf::Sessions
  #
  # Shared output-buffering and polling logic for the WinRM stream adapters
  # (Msf::Sessions::WinrmCommandShell::WinRMStreamAdapter and
  # Msf::Sessions::WinrmPowerShell::WinRMPowerShellStreamAdapter). Both
  # adapters receive output on a background thread and buffer it for
  # Msf::Session::Provider::SingleCommandShell to read via #get_once.
  #
  module WinrmStreamAdapterCommon
    # Includers must call this from #initialize before using #get_once,
    # #_get_once, or #append_output.
    def init_stream_buffer
      @buffer_mutex = Mutex.new
      @buffer = []
      # auto_reset is false: #get_once resets the event itself after every
      # wake-up, immediately before it re-checks the buffer. If the event
      # auto-reset on #set instead, a #set landing between that buffer check
      # and the call to #wait would be missed (a classic lost wakeup),
      # leaving the reader blocked for the full timeout even though output
      # was already sitting in the buffer.
      @received_stdout_event = Rex::Sync::Event.new(false, false)
    end

    def peerinfo
      shell.transport.peerinfo
    end

    def localinfo
      shell.transport.localinfo
    end

    ##
    # :category: Msf::Session::Provider::SingleCommandShell implementors
    #
    # Read buffered output received from the background thread. Yields
    # (if a block is given) each time we're about to loop back and wait
    # again, so includers can nudge their background thread along.
    #
    def get_once(length = -1, timeout = 1)
      start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      result = ''
      loop do
        result = _get_once(length)
        elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time
        time_remaining = timeout - elapsed
        break if result != '' || time_remaining <= 0

        # rubocop:disable Lint/SuppressedException
        begin
          @received_stdout_event.wait(time_remaining)
        rescue ::Timeout::Error
        ensure
          @received_stdout_event.reset
        end
        # rubocop:enable Lint/SuppressedException
        yield if block_given?
      end
      result
    end

    def _get_once(length)
      result = ''
      @buffer_mutex.synchronize do
        result = @buffer.join('')
        @buffer = []
        if (length > -1) && (result.length > length)
          # Return up to length, and keep the rest in the buffer.
          extra = result[length..]
          result = result[0, length]
          @buffer << extra
        end
      end
      result
    end
  end
end
