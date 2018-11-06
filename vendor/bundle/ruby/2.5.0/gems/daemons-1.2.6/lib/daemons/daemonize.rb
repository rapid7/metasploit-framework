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
  # NOTE: $stdout and $stderr will not be redirected to the logfile,
  # because in :ontop mode, we normally want to see the output
  def simulate(logfile_name = nil, app_name = nil)
    $0 = app_name if app_name

    # Release old working directory
    Dir.chdir '/'

    close_io

    # Free $stdin and point it to somewhere sensible
    begin; $stdin.reopen '/dev/null'; rescue ::Exception; end

    # Split rand streams between spawning and daemonized process
    srand
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
      unless Process.setsid
        fail Daemons.RuntimeException.new('cannot detach from controlling terminal')
      end

      # Prevent the possibility of acquiring a controlling terminal
      trap 'SIGHUP', 'IGNORE'
      exit if pid = safefork

      wr.write Process.pid
      wr.close

      $0 = app_name if app_name

      # Release old working directory
      Dir.chdir '/'

      close_io

      redirect_io(logfile_name)

      # Split rand streams between spawning and daemonized process
      srand

      block.call

      exit
    end
  end
  module_function :call_as_daemon

  # Transform the current process into a daemon
  def daemonize(logfile_name = nil, app_name = nil)
    # Fork and exit from the parent
    safefork && exit

    # Detach from the controlling terminal
    unless sess_id = Process.setsid
      fail Daemons.RuntimeException.new('cannot detach from controlling terminal')
    end

    # Prevent the possibility of acquiring a controlling terminal
    trap 'SIGHUP', 'IGNORE'
    exit if safefork

    $0 = app_name if app_name

    # Release old working directory
    Dir.chdir '/'

    close_io

    redirect_io(logfile_name)

    # Split rand streams between spawning and daemonized process
    srand

    sess_id
  end
  module_function :daemonize

  def close_io
    # Make sure all input/output streams are closed
    # Part I: close all IO objects (except for $stdin/$stdout/$stderr)
    ObjectSpace.each_object(IO) do |io|
      unless [$stdin, $stdout, $stderr].include?(io)
        io.close rescue nil
      end
    end

    # Make sure all input/output streams are closed
    # Part II: close all file decriptors (except for $stdin/$stdout/$stderr)
    3.upto(8192) do |i|
      IO.for_fd(i).close rescue nil
    end
  end
  module_function :close_io

  # Free $stdin/$stdout/$stderr file descriptors and
  # point them somewhere sensible
  def redirect_io(logfile_name)
    begin; $stdin.reopen '/dev/null'; rescue ::Exception; end

    if logfile_name == 'SYSLOG'
      # attempt to use syslog via syslogio
      begin
        require 'syslogio'
        $stdout = ::Daemons::SyslogIO.new($0, :local0, :info, $stdout)
        $stderr = ::Daemons::SyslogIO.new($0, :local0, :err, $stderr)
        # error out early so we can fallback to null
        $stdout.puts "no logfile provided, output redirected to syslog"
      rescue ::Exception
        # on unsupported platforms simply reopen /dev/null
        begin; $stdout.reopen '/dev/null'; rescue ::Exception; end
        begin; $stderr.reopen '/dev/null'; rescue ::Exception; end
      end
    elsif logfile_name
      $stdout.reopen logfile_name, 'a'
      File.chmod(0644, logfile_name)
      $stdout.sync = true
      begin; $stderr.reopen $stdout; rescue ::Exception; end
      $stderr.sync = true
    else
      begin; $stdout.reopen '/dev/null'; rescue ::Exception; end
      begin; $stderr.reopen '/dev/null'; rescue ::Exception; end
    end
  end
  module_function :redirect_io
end
