require 'optparse'
require 'optparse/time'


require 'daemons/pidfile'  
require 'daemons/cmdline'
require 'daemons/exceptions'
require 'daemons/monitor'


require 'daemons/application'
require 'daemons/application_group'
require 'daemons/controller'

require 'timeout'

# All functions and classes that Daemons provides reside in this module.
#
# Daemons is normally invoked by one of the following four ways:
#
# 1.  <tt>Daemons.run(script, options)</tt>:
#     This is used in wrapper-scripts that are supposed to control other ruby scripts or
#     external applications. Control is completely passed to the daemons library.
#     Such wrapper script need to be invoked with command line options like 'start' or 'stop'
#     to do anything useful.
#
# 2.  <tt>Daemons.run_proc(app_name, options) { (...) }</tt>:
#     This is used in wrapper-scripts that are supposed to control a proc. 
#     Control is completely passed to the daemons library.
#     Such wrapper scripts need to be invoked with command line options like 'start' or 'stop'
#     to do anything useful.
#
# 3.  <tt>Daemons.call(options) { block }</tt>:
#     Execute the block in a new daemon. <tt>Daemons.call</tt> will return immediately
#     after spawning the daemon with the new Application object as a return value.
#
# 4.  <tt>Daemons.daemonize(options)</tt>:
#     Daemonize the currently runnig process, i.e. the calling process will become a daemon.
#
# == What does daemons internally do with my daemons?
# *or*:: why do my daemons crash when they try to open a file?
# *or*:: why can I not see any output from the daemon on the console (when using for example +puts+)?
#
# From a technical aspect of view, daemons does the following when creating a daemon:
#
# 1.  Forks a child (and exits the parent process, if needed)
# 2.  Becomes a session leader (which detaches the program from
#     the controlling terminal).
# 3.  Forks another child process and exits first child. This prevents
#     the potential of acquiring a controlling terminal.
# 4.  Changes the current working directory to "/".
# 5.  Clears the file creation mask (sets +umask+ to 0000).
# 6.  Closes file descriptors (reopens +STDOUT+ and +STDERR+ to point to a logfile if
#     possible).
#
# So what does this mean for your daemons:
# - the current directory is '/'
# - you cannot receive any input from the console (for example no +gets+)
# - you cannot output anything from the daemons with +puts+/+print+ unless a logfile is used
#
# == How do PidFiles work? Where are they stored?
#
# Also, you are maybe interested in reading the documentation for the class PidFile.
# There you can find out about how Daemons works internally and how and where the so
# called <i>PidFiles</i> are stored.
#
module Daemons

  VERSION = "1.1.8"
  
  require 'daemons/daemonize'
  
  
  # Passes control to Daemons.
  # This is used in wrapper-scripts that are supposed to control other ruby scripts or
  # external applications. Control is completely passed to the daemons library.
  # Such wrapper script should be invoked with command line options like 'start' or 'stop'
  # to do anything useful.
  #
  # +script+::  This is the path to the script that should be run as a daemon.
  #             Please note that Daemons runs this script with <tt>load <script></tt>.
  #             Also note that Daemons cannot detect the directory in which the controlling
  #             script resides, so this has to be either an absolute path or you have to run
  #             the controlling script from the appropriate directory. Your script name should not
  #             end with _monitor because that name is reserved for a monitor process which is 
  #             there to restart your daemon if it crashes.
  #
  # +options+:: A hash that may contain one or more of the options listed below
  #
  # === Options:
  # <tt>:app_name</tt>::  The name of the application. This will be
  #                       used to contruct the name of the pid files
  #                       and log files. Defaults to the basename of
  #                       the script.
  # <tt>:ARGV</tt>::      An array of strings containing parameters and switches for Daemons.
  #                       This includes both parameters for Daemons itself and the controlled scripted.
  #                       These are assumed to be separated by an array element '--', .e.g.
  #                       ['start', 'f', '--', 'param1_for_script', 'param2_for_script'].
  #                       If not given, ARGV (the parameters given to the Ruby process) will be used.
  # <tt>:dir_mode</tt>::  Either <tt>:script</tt> (the directory for writing the pid files to 
  #                       given by <tt>:dir</tt> is interpreted relative
  #                       to the script location given by +script+, the default) or <tt>:normal</tt> (the directory given by 
  #                       <tt>:dir</tt> is interpreted as a (absolute or relative) path) or <tt>:system</tt> 
  #                       (<tt>/var/run</tt> is used as the pid file directory)
  #
  # <tt>:dir</tt>::       Used in combination with <tt>:dir_mode</tt> (description above)
  # <tt>:multiple</tt>::  Specifies whether multiple instances of the same script are allowed to run at the
  #                       same time
  # <tt>:ontop</tt>::     When given (i.e. set to true), stay on top, i.e. do not daemonize the application 
  #                       (but the pid-file and other things are written as usual)
  # <tt>:mode</tt>::      <tt>:load</tt> Load the script with <tt>Kernel.load</tt>;
  #                       note that :stop_proc only works for the :load (and :proc) mode.
  #                       <tt>:exec</tt> Execute the script file with <tt>Kernel.exec</tt>
  # <tt>:backtrace</tt>:: Write a backtrace of the last exceptions to the file '[app_name].log' in the 
  #                       pid-file directory if the application exits due to an uncaught exception
  # <tt>:monitor</tt>::   Monitor the programs and restart crashed instances
  # <tt>:log_dir</tt>::   A specific directory to put the log files into (when not given, resort to the default
  #                       location as derived from the :dir_mode and :dir options
  # <tt>:log_output</tt>:: When given (i.e. set to true), redirect both STDOUT and STDERR to a logfile named '[app_name].output' in the pid-file directory
  # <tt>:keep_pid_files</tt>:: When given do not delete lingering pid-files (files for which the process is no longer running).
  # <tt>:hard_exit</tt>:: When given use exit! to end a daemons instead of exit (this will for example
  #                       not call at_exit handlers).
  # <tt>:stop_proc</tt>:: A proc that will be called when the daemonized process receives a request to stop (works only for :load and :proc mode)
  #
  # -----
  # 
  # === Example:
  #   options = {
  #     :app_name   => "my_app",
  #     :ARGV       => ['start', '-f', '--', 'param_for_myscript']
  #     :dir_mode   => :script,
  #     :dir        => 'pids',
  #     :multiple   => true,
  #     :ontop      => true,
  #     :mode       => :exec,
  #     :backtrace  => true,
  #     :monitor    => true
  #   }
  #
  #   Daemons.run(File.join(File.dirname(__FILE__), 'myscript.rb'), options)
  #
  def run(script, options = {})
    options[:script] = script
    @controller = Controller.new(options, options[:ARGV] || ARGV)
    
    @controller.catch_exceptions {
      @controller.run
    }
    
    # I don't think anybody will ever use @group, as this location should not be reached under non-error conditions
    @group = @controller.group
  end
  module_function :run
  
  
  # Passes control to Daemons.
  # This function does the same as Daemons.run except that not a script but a proc
  # will be run as a daemon while this script provides command line options like 'start' or 'stop'
  # and the whole pid-file management to control the proc.
  #
  # +app_name+::  The name of the application. This will be
  #               used to contruct the name of the pid files
  #               and log files. Defaults to the basename of
  #               the script.
  # 
  # +options+::   A hash that may contain one or more of the options listed in the documentation for Daemons.run
  #
  # A block must be given to this function. The block will be used as the :proc entry in the options hash.
  #
  # -----
  # 
  # === Example:
  #
  #   Daemons.run_proc('myproc.rb') do
  #     loop do
  #       accept_connection()
  #       read_request()
  #       send_response()
  #       close_connection()
  #     end
  #   end
  #
  def run_proc(app_name, options = {}, &block)
    options[:app_name] = app_name
    options[:mode] = :proc
    options[:proc] = block
    
    # we do not have a script location so the the :script :dir_mode cannot be used, change it to :normal
    if [nil, :script].include? options[:dir_mode]
      options[:dir_mode] = :normal
      options[:dir] ||= File.expand_path('.')
    end
    
    @controller = Controller.new(options, options[:ARGV] || ARGV)
    
    @controller.catch_exceptions {
      @controller.run
    }
    
    # I don't think anybody will ever use @group, as this location should not be reached under non-error conditions
    @group = @controller.group
  end
  module_function :run_proc
  
  
  # Execute the block in a new daemon. <tt>Daemons.call</tt> will return immediately
  # after spawning the daemon with the new Application object as a return value.
  #
  # +app_name+::  The name of the application.
  #
  # +options+:: A hash that may contain one or more of the options listed below
  #
  # +block+::   The block to call in the daemon.
  #
  # === Options:
  # <tt>:multiple</tt>::  Specifies whether multiple instances of the same script are allowed to run at the
  #                       same time
  # <tt>:ontop</tt>::     When given, stay on top, i.e. do not daemonize the application 
  # <tt>:backtrace</tt>:: Write a backtrace of the last exceptions to the file '[app_name].log' in the 
  #                       pid-file directory if the application exits due to an uncaught exception
  # -----
  # 
  # === Example:
  #   options = {
  #     :app_name   => "myproc",
  #     :backtrace  => true,
  #     :monitor    => true,
  #     :ontop      => true
  #   }
  #
  #   Daemons.call(options) begin
  #     # Server loop:
  #     loop {
  #       conn = accept_conn()
  #       serve(conn)
  #     }
  #   end
  #
  def call(options = {}, &block)
    unless block_given?
      raise "Daemons.call: no block given"
    end
    
    options[:proc] = block
    options[:mode] = :proc
    
    options[:app_name] ||= 'proc'
    
    @group ||= ApplicationGroup.new(options[:app_name], options)
    
    new_app = @group.new_application(options)
    new_app.start

    return new_app
  end
  module_function :call
  
  
  # Daemonize the currently runnig process, i.e. the calling process will become a daemon.
  #
  # +options+:: A hash that may contain one or more of the options listed below
  #
  # === Options:
  # <tt>:ontop</tt>::     When given, stay on top, i.e. do not daemonize the application 
  # <tt>:backtrace</tt>:: Write a backtrace of the last exceptions to the file '[app_name].log' in the 
  #                       pid-file directory if the application exits due to an uncaught exception
  # <tt>:app_name</tt>::  The name of the application. This will be
  #                       used to contruct the name of the pid files
  #                       and log files. Defaults to the basename of
  #                       the script.
  # <tt>:dir_mode</tt>::  Either <tt>:script</tt> (the directory for writing files to 
  #                       given by <tt>:dir</tt> is interpreted relative
  #                       to the script location given by +script+, the default) or <tt>:normal</tt> (the directory given by 
  #                       <tt>:dir</tt> is interpreted as a (absolute or relative) path) or <tt>:system</tt> 
  #                       (<tt>/var/run</tt> is used as the file directory)
  #
  # <tt>:dir</tt>::       Used in combination with <tt>:dir_mode</tt> (description above)
  # <tt>:log_dir</tt>::   A specific directory to put the log files into (when not given, resort to the default
  #                       location as derived from the :dir_mode and :dir options
  # <tt>:log_output</tt>:: When given (i.e. set to true), redirect both STDOUT and STDERR to a logfile named '[app_name].output' in the pid-file directory
  # -----
  # 
  # === Example:
  #   options = {
  #     :backtrace  => true,
  #     :ontop      => true,
  #     :log_output => true
  #   }
  #
  #   Daemons.daemonize(options)
  #
  #   # Server loop:
  #   loop {
  #     conn = accept_conn()
  #     puts "some text which goes to the output logfile"
  #     serve(conn)
  #   }
  #
  def daemonize(options = {})
    options[:script] ||= File.basename(__FILE__)
    
    @group ||= ApplicationGroup.new(options[:app_name] || options[:script], options)
    
    @group.new_application(:mode => :none).start
  end
  module_function :daemonize
  
  # Return the internal ApplicationGroup instance.
  def group; @group; end
  module_function :group
  
  # Return the internal Controller instance.
  def controller; @controller; end
  module_function :controller
end 
