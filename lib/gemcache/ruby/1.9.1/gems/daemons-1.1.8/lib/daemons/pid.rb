

module Daemons

  class Pid
  
    def Pid.running?(pid)
      return false unless pid
      
      # Check if process is in existence
      # The simplest way to do this is to send signal '0'
      # (which is a single system call) that doesn't actually
      # send a signal
      begin
        Process.kill(0, pid)
        return true
      rescue Errno::ESRCH
        return false
      rescue ::Exception   # for example on EPERM (process exists but does not belong to us)
        return true
      #rescue Errno::EPERM
      #  return false
      end
    end
    
  #  def Pid.running?(pid, additional = nil)
  #    match_pid = Regexp.new("^\\s*#{pid}\\s")
  #    got_match = false
  #
  #    #ps_all = IO.popen('ps ax') # the correct syntax is without a dash (-) !
  #    ps_in, ps_out, ps_err = Open3.popen3('ps ax') # the correct syntax is without a dash (-) !
  #    
  #    return true unless ps_out.gets
  #    
  #    begin
  #      ps_out.each { |psline|
  #        next unless psline =~ match_pid
  #        got_match = true
  #        got_match = false if additional and psline !~ /#{additional}/
  #        break
  #      }
  #    ensure
  #      begin; begin; ps_in.close; rescue ::Exception; end; begin; ps_out.close; rescue ::Exception; end; ps_err.close; rescue ::Exception; end
  #    end
  #    
  #    # an alternative would be to use the code below, but I don't know whether this is portable
  #    # `ps axo pid=`.split.include? pid.to_s
  #     
  #    return got_match
  #  end
    
    
    
    # Returns the directory that should be used to write the pid file to
    # depending on the given mode.
    # 
    # Some modes may require an additionaly hint, others may determine 
    # the directory automatically.
    #
    # If no valid directory is found, returns nil.
    #
    def Pid.dir(dir_mode, dir, script)
      # nil script parameter is allowed as long as dir_mode is not :script
      return nil if dir_mode == :script && script.nil?                         
      
      case dir_mode
        when :normal
          return File.expand_path(dir)
        when :script
          return File.expand_path(File.join(File.dirname(script),dir))
        when :system  
          return '/var/run'
        else
          raise Error.new("pid file mode '#{dir_mode}' not implemented")
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
      return Pid.running?(pid())
    end
    
    # Cleanup method
    def cleanup
    end
    
    # Exist? method
    def exist?
      true
    end
    
  end  
  
  
end