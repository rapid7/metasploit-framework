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
    # Create a session instance from a shell ID.
    #
    # @param shell [WinRM::Shells::Base] A WinRM shell object
    # @param opts [Hash] Optional parameters to pass to the session object.
    def initialize(shell, addr, port, opts = {})
      self.shell = shell
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
          if sd 
            run_single((user_input.gets || '').chomp("\n"))
          end

          # We may receive output at any time, so ask every time, even if no input
          shell.read_stdout do |stdout, stderr|
            user_output.print(stdout) if stdout
            user_output.print(stderr) if stderr
          end
        rescue WinRM::WinRMWSManFault => err
          print_error(err.fault_description)
          shell_close
        end
        Thread.pass
      end
    end

    def tunnel_to_s
      'WinRM'
    end

protected
		attr_accessor :shell

  end
end
