module EventMachine
  # Utility class that is useful for file monitoring. Supported events are
  #
  # * File is modified
  # * File is deleted
  # * File is moved
  #
  # @note On Mac OS X, file watching only works when kqueue is enabled
  #
  # @see EventMachine.watch_file
  class FileWatch < Connection
    # @private
    Cmodified = 'modified'.freeze
    # @private
    Cdeleted = 'deleted'.freeze
    # @private
    Cmoved = 'moved'.freeze


    # @private
    def receive_data(data)
      case data
      when Cmodified
        file_modified
      when Cdeleted
        file_deleted
      when Cmoved
        file_moved
      end
    end

    # Returns the path that is being monitored.
    #
    # @note Current implementation does not pick up on the new filename after a rename occurs.
    #
    # @return [String]
    # @see EventMachine.watch_file
    def path
      @path
    end

    # Will be called when the file is modified. Supposed to be redefined by subclasses.
    #
    # @abstract
    def file_modified
    end

    # Will be called when the file is deleted. Supposed to be redefined by subclasses.
    # When the file is deleted, stop_watching will be called after this to make sure everything is
    # cleaned up correctly.
    #
    # @note On Linux (with {http://en.wikipedia.org/wiki/Inotify inotify}), this method will not be called until *all* open file descriptors to
    #       the file have been closed.
    #
    # @abstract
    def file_deleted
    end

    # Will be called when the file is moved or renamed. Supposed to be redefined by subclasses.
    #
    # @abstract
    def file_moved
    end

    # Discontinue monitoring of the file.
    #
    # This involves cleaning up the underlying monitoring details with kqueue/inotify, and in turn firing {EventMachine::Connection#unbind}.
    # This will be called automatically when a file is deleted. User code may call it as well.
    def stop_watching
      EventMachine::unwatch_filename(@signature)
    end # stop_watching
  end # FileWatch
end # EventMachine
