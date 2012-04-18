module EventMachine

  # This is subclassed from EventMachine::Connection for use with the process monitoring API. Read the
  # documentation on the instance methods of this class, and for a full explanation see EventMachine.watch_process.
  class ProcessWatch < Connection
    # @private
    Cfork = 'fork'.freeze
    # @private
    Cexit = 'exit'.freeze

    # @private
    def receive_data(data)
      case data
      when Cfork
        process_forked
      when Cexit
        process_exited
      end
    end

    # Returns the pid that EventMachine::watch_process was originally called with.
    def pid
      @pid
    end

    # Should be redefined with the user's custom callback that will be fired when the prcess is forked.
    #
    # There is currently not an easy way to get the pid of the forked child.
    def process_forked
    end

    # Should be redefined with the user's custom callback that will be fired when the process exits.
    #
    # stop_watching is called automatically after this callback
    def process_exited
    end

    # Discontinue monitoring of the process.
    # This will be called automatically when a process dies. User code may call it as well.
    def stop_watching
      EventMachine::unwatch_pid(@signature)
    end
  end

end
