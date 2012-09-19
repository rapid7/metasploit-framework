module Daemonize
  
  # Try to fork if at all possible retrying every 5 sec if the
  # maximum process limit for the system has been reached
  def safefork
    tryagain = true

    while tryagain
      tryagain = false
      begin
        if pid = fork
          return pid
        end
      rescue Errno::EWOULDBLOCK
        sleep 5
        tryagain = true
      end
    end
  end
  module_function :safefork
  
  
  # Simulate the daemonization process (:ontop mode)
  # NOTE: STDOUT and STDERR will not be redirected to the logfile, 
  # because in :ontop mode, we normally want to see the output
  def simulate(logfile_name = nil)
    # Release old working directory
    Dir.chdir "/"   

    close_io()

    # Free STDIN and point them somewhere sensible
    begin; STDIN.reopen "/dev/null"; rescue ::Exception; end       
  end
  module_function :simulate
  
  
  # Call a given block as a daemon
  def call_as_daemon(block, logfile_name = nil, app_name = nil)
    # we use a pipe to return the PID of the daemon
    rd, wr = IO.pipe
    
    if tmppid = safefork
      # in the parent
      
      wr.close
      pid = rd.read.to_i
      rd.close
      
      Process.waitpid(tmppid)
      
      return pid
    else
      # in the child
      
      rd.close
      
      # Detach from the controlling terminal
      unless sess_id = Process.setsid
        raise Daemons.RuntimeException.new('cannot detach from controlling terminal')
      end
  
      # Prevent the possibility of acquiring a controlling terminal
      trap 'SIGHUP', 'IGNORE'
      exit if pid = safefork
  
      wr.write Process.pid
      wr.close
      
      $0 = app_name if app_name
      
      # Release old working directory
      Dir.chdir "/"   
  
      close_io()

      redirect_io(logfile_name)  
    
      block.call
      
      exit
    end
  end
  module_function :call_as_daemon
  
  
  # Transform the current process into a daemon
  def daemonize(logfile_name = nil, app_name = nil)
    # Split rand streams between spawning and daemonized process
    srand 
    
     # Fork and exit from the parent
    safefork and exit

    # Detach from the controlling terminal
    unless sess_id = Process.setsid
      raise Daemons.RuntimeException.new('cannot detach from controlling terminal')
    end

    # Prevent the possibility of acquiring a controlling terminal
    trap 'SIGHUP', 'IGNORE'
    exit if pid = safefork
    
    $0 = app_name if app_name
    
    # Release old working directory
    Dir.chdir "/"  

    close_io()

    redirect_io(logfile_name)
    
    return sess_id
  end
  module_function :daemonize
  
  
  def close_io()
    # Make sure all input/output streams are closed
    # Part I: close all IO objects (except for STDIN/STDOUT/STDERR)
    ObjectSpace.each_object(IO) do |io|
      unless [STDIN, STDOUT, STDERR].include?(io)
        begin
          unless io.closed?
            io.close
          end
        rescue ::Exception
        end
      end
    end
    
    # Make sure all input/output streams are closed
    # Part II: close all file decriptors (except for STDIN/STDOUT/STDERR)
    ios = Array.new(8192) {|i| IO.for_fd(i) rescue nil}.compact
    ios.each do |io|
      next if io.fileno < 3
      io.close
    end
  end
  module_function :close_io
  
  
  # Free STDIN/STDOUT/STDERR file descriptors and
  # point them somewhere sensible
  def redirect_io(logfile_name)
    begin; STDIN.reopen "/dev/null"; rescue ::Exception; end       
     
    if logfile_name
      begin
        STDOUT.reopen logfile_name, "a" 
        File.chmod(0644, logfile_name)
        STDOUT.sync = true
      rescue ::Exception
        begin; STDOUT.reopen "/dev/null"; rescue ::Exception; end
      end
    else
      begin; STDOUT.reopen "/dev/null"; rescue ::Exception; end
    end
    
    begin; STDERR.reopen STDOUT; rescue ::Exception; end
    STDERR.sync = true
  end
  module_function :redirect_io
  
  
end
