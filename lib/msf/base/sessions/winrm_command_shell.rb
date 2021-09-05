# -*- coding: binary -*-

require 'msf/core/exploit/remote/winrm'
require 'winrm'

module Msf::Sessions
  #
  # This class provides a session for WinRM client connections, where Metasploit
  # has authenticated to a remote WinRM instance.
  #
  class WinrmCommandShell < Msf::Sessions::CommandShell

    def commands
      {
        'help'       => 'Help menu',
        'background' => 'Backgrounds the current shell session',
        'sessions'   => 'Quickly switch to another session',
        'resource'   => 'Run a meta commands script stored in a local file',
        'irb'        => 'Open an interactive Ruby shell on the current session',
        'pry'        => 'Open the Pry debugger on the current session',
      }
    end

    #
    # Create an MSF command shell from a WinRM shell object
    #
    # @param shell [WinRM::Shells::Base] A WinRM shell object
    # @param opts [Hash] Optional parameters to pass to the session object.
    def initialize(shell, opts = {})
      self.shell = shell
      # To buffer input received while a session is backgrounded, we stick responses in a list
      @buffer_mutex = Mutex.new
      @buffer = []
      super(nil, opts)
    end

    def shell_write(buf)
      return unless buf

      begin
        framework.events.on_session_command(self, buf.strip)
        shell.send_stdin(buf)
      rescue ::Rex::SocketError, ::EOFError, ::IOError, ::Errno::EPIPE => e
        shell_close
        raise e
      end
    end

    def cleanup
      begin
        stop_keep_alive_loop
        shell.cleanup_shell
      rescue WinRM::WinRMWSManFault => err
        print_error('Shell may not have terminated cleanly')
      end
    end

    ##
    # :category: Msf::Session::Interactive implementors
    #
    def _interact_stream
      fds = [user_input.fd]
      while self.interacting
        sd = Rex::ThreadSafe.select(fds, nil, fds, 0.5)
        begin
          @buffer_mutex.synchronize {
            @buffer.each { |buf| user_output.print(buf) }
            @buffer = []
          }
          if sd 
            run_single((user_input.gets || '').chomp("\n"))
          end
          
        rescue WinRM::WinRMWSManFault => err
          print_error(err.fault_description)
          shell_close
        end
        Thread.pass
      end
    end

    def on_registered
      start_keep_alive_loop
    end

    def start_keep_alive_loop
      self.keep_alive_thread = framework.threads.spawn("WinRM-shell-keepalive", false, self.shell) do |thr_shell|
        loop do
          tmp_buffer = []
          shell.read_stdout do |stdout, stderr|
            tmp_buffer << stdout if stdout
            tmp_buffer << stderr if stderr
          end
          @buffer_mutex.synchronize {
            @buffer.concat(tmp_buffer)
          }
          sleep(1)
        rescue WinRM::WinRMWSManFault => err
          print_error(err.fault_description)
          detected_shell_ended
        rescue EOFError
          # Shell has been terminated
          detected_shell_ended
        rescue Rex::HostUnreachable => err
          detected_shell_ended(err.message)
        rescue StandardError => err
          detected_shell_ended(err.message)
        end
      end
    end

    def detected_shell_ended(reason="")
      self.interacting = false
      framework.events.on_session_interact_completed()
      framework.sessions.deregister(self, reason)
    end

    def stop_keep_alive_loop
      self.keep_alive_thread.kill
    end

    def tunnel_to_s
      'WinRM'
    end

protected
		attr_accessor :shell, :keep_alive_thread

  end
end
