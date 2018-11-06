require 'daemons/exceptions'

module Daemons
  class Pid
    def self.running?(pid)
      return false unless pid

      # Check if process is in existence
      # The simplest way to do this is to send signal '0'
      # (which is a single system call) that doesn't actually
      # send a signal
      begin
        Process.kill(0, pid)
        return true
      rescue TimeoutError
        raise
      rescue Errno::ESRCH
        return false
      rescue ::Exception   # for example on EPERM (process exists but does not belong to us)
        return true
      end
    end

    # Returns the directory that should be used to write the pid file to
    # depending on the given mode.
    #
    # Some modes may require an additionaly hint, others may determine
    # the directory automatically.
    #
    # If no valid directory is found, returns nil.
    #
    def self.dir(dir_mode, dir, script)
      # nil script parameter is allowed as long as dir_mode is not :script
      return nil if dir_mode == :script && script.nil?

      case dir_mode
        when :normal
          return File.expand_path(dir)
        when :script
          return File.expand_path(File.join(File.dirname(script), dir))
        when :system
          return '/var/run'
        else
          fail Error.new("pid file mode '#{dir_mode}' not implemented")
      end
    end

    # Initialization method
    def initialize
    end

    # Get method
    def pid
    end

    # Set method
    def pid=(p)
    end

    # Check whether the process is running
    def running?
      Pid.running?(pid)
    end

    # Cleanup method
    def cleanup
    end
    
    # Zap method
    def zap
    end

    # Exist? method
    def exist?
      true
    end
  end
end
