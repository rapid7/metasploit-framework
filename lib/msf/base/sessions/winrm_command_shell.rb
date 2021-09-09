# -*- coding: binary -*-

require 'winrm'

module Msf::Sessions
  #
  # This class provides a session for WinRM client connections, where Metasploit
  # has authenticated to a remote WinRM instance.
  #
  class WinrmCommandShell < Msf::Sessions::PowerShell

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
      @check_stdin_event = Rex::Sync::Event.new(false, true)
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

  ##
  # :category: Msf::Session::Provider::SingleCommandShell implementors
  #
  # Read from the command shell.
  #
  def shell_read(length=-1, timeout=1)
    result = ""
    @buffer_mutex.synchronize {
      result = @buffer.join("")
      @buffer = []
      if length > -1 and result.length > length
        # Return up to length, and keep the rest in the buffer
        extra = result[length..-1]
        result = result[0,length]
        @buffer << extra
      end
    }
    result
  end

    def cleanup
      begin
        stop_keep_alive_loop
        shell.cleanup_shell
      rescue WinRM::WinRMWSManFault => err
        print_error('Shell may not have terminated cleanly')
      end
    end

    def abort_foreground
      shell.send_ctrl_c
    end

    ##
    # :category: Msf::Session::Interactive implementors
    #
    def _interact_stream
      fds = [user_input.fd]
      while self.interacting
        sd = Rex::ThreadSafe.select(fds, nil, fds, 0.5)
        begin
          user_output.print(shell_read)
          if sd 
            run_single((user_input.gets || '').chomp("\n")+"\r")
            @check_stdin_event.set()
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
        loop_delay = 0.5
        loop do
          tmp_buffer = []
          output_seen = false
          shell.read_stdout do |stdout, stderr|
            if stdout or stderr
              output_seen = true
            end
            tmp_buffer << stdout if stdout
            tmp_buffer << stderr if stderr
          end
          @buffer_mutex.synchronize {
            @buffer.concat(tmp_buffer)
          }

          # If our last request received stdout, let's be ready for some more
          if output_seen
            loop_delay = 0.5
          else
            # Gradual backoff
            loop_delay *= 4
            loop_delay = [loop_delay, 30].min
          end

          # Wait loop_delay seconds, or until an interactive thread wakes us up
          begin
            @check_stdin_event.wait(loop_delay)
          rescue TimeoutError
          end
          Thread.pass
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

    def tunnel_peer
      self.shell.transport.peerinfo
    end

    def tunnel_local
      self.shell.transport.localinfo
    end

protected
		attr_accessor :shell, :keep_alive_thread

  end
end
