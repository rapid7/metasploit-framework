# -*- coding: binary -*-
# frozen_string_literal: true

require 'winrm'

module Msf::Sessions
  #
  # This class provides a PowerShell session for WinRM client connections, where
  # Metasploit has authenticated to a remote WinRM instance and is using a PSRP
  # runspace rather than a WinRS command shell.
  #
  class WinrmPowerShell < Msf::Sessions::PowerShell

    # Abstract WinRM PowerShell to look like a stream so CommandShell can be happy.
    class WinRMPowerShellStreamAdapter
      # @param shell [WinRM::Shells::PowerShell] Shell for talking to the WinRM service
      # @param on_shell_ended [Method] Callback for when the background thread notices the shell has ended.
      def initialize(shell, on_shell_ended)
        # To buffer input received while a session is backgrounded, we stick responses in a list.
        @buffer_mutex = Mutex.new
        @buffer = []
        @pipeline_mutex = Mutex.new
        @received_stdout_event = Rex::Sync::Event.new(false, true)
        self.shell = shell
        self.on_shell_ended = on_shell_ended
      end

      def peerinfo
        shell.transport.peerinfo
      end

      def localinfo
        shell.transport.localinfo
      end

      def write(buf)
        return if buf.nil? || buf.empty?

        run_pipeline(buf)
      end

      ##
      # :category: Msf::Session::Provider::SingleCommandShell implementors
      #
      # Read from the PowerShell pipeline output buffer.
      #
      def get_once(length = -1, timeout = 1)
        start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        result = ''
        loop do
          result = _get_once(length)
          elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time
          time_remaining = timeout - elapsed
          break if result != '' || time_remaining <= 0

          # rubocop:disable Lint/SuppressedException
          begin
            @received_stdout_event.wait(time_remaining)
          rescue ::Timeout::Error
          end
          # rubocop:enable Lint/SuppressedException
        end
        result
      end

      def _get_once(length)
        result = ''
        @buffer_mutex.synchronize do
          result = @buffer.join('')
          @buffer = []
          if (length > -1) && (result.length > length)
            # Return up to length, and keep the rest in the buffer.
            extra = result[length..]
            result = result[0, length]
            @buffer << extra
          end
        end
        result
      end

      # Close the shell; cleanly terminating it on the server if possible.
      #
      # The shell may already be dead, or unreachable at this point, so do a best
      # effort, and capture exceptions.
      # rubocop:disable Lint/SuppressedException
      def close
        active_pipeline_thread.kill if active_pipeline_thread&.alive?
        shell.close
      rescue WinRM::WinRMWSManFault
      end
      # rubocop:enable Lint/SuppressedException

      attr_accessor :shell, :on_shell_ended, :framework, :active_pipeline_thread

      private

      def run_pipeline(script)
        self.active_pipeline_thread = spawn_thread(script) do |pipeline_script|
          @pipeline_mutex.synchronize do
            shell.run(pipeline_script) do |stdout, stderr|
              append_output(stdout) if stdout
              append_output(stderr) if stderr
            end
          end
        rescue WinRM::WinRMWSManFault => e
          append_output(e.fault_description)
          on_shell_ended.call(e.fault_description)
        rescue EOFError
          on_shell_ended.call
        rescue Rex::HostUnreachable => e
          on_shell_ended.call(e.message)
        rescue StandardError => e
          append_output(e.message)
          on_shell_ended.call(e.message)
        end
      end

      def spawn_thread(script, &block)
        if framework&.threads
          framework.threads.spawn('WinRM-PowerShell-pipeline', false, script, &block)
        else
          Thread.new(script, &block)
        end
      end

      def append_output(data)
        output = data.to_s.gsub(/\r?\n/, "\r\n")
        @buffer_mutex.synchronize do
          @buffer << output
        end
        @received_stdout_event.set
      end
    end

    def commands
      {
        'help' => 'Help menu',
        'background' => 'Backgrounds the current shell session',
        'sessions' => 'Quickly switch to another session',
        'resource' => 'Run a meta commands script stored in a local file',
        'irb' => 'Open an interactive Ruby shell on the current session',
        'pry' => 'Open the Pry debugger on the current session'
      }
    end

    #
    # Create an MSF PowerShell session from a WinRM PowerShell shell object.
    #
    # @param shell [WinRM::Shells::PowerShell] A WinRM PowerShell shell object
    # @param opts [Hash] Optional parameters to pass to the session object.
    def initialize(shell, opts = {})
      self.shell = shell
      self.adapter = WinRMPowerShellStreamAdapter.new(self.shell, method(:shell_ended))
      super(adapter, opts)
    end

    def abort_foreground_supported
      # The default abort_foreground writes a Ctrl+C byte to the stream, which
      # would be submitted as a new PSRP pipeline rather than signaling the
      # active one. Supporting this requires tracking and signaling the active
      # pipeline command ID, which WinRM::Shells::Powershell#run does not expose.
      false
    end

    def desc
      'WinRM PowerShell'
    end

    def process_autoruns(datastore)
      Msf::Sessions::CommandShell.instance_method(:process_autoruns).bind(self).call(datastore)
    end

    ##
    # :category: Msf::Session::Interactive implementors
    #
    def _interact_stream
      fds = [user_input.fd]
      while interacting
        sd = Rex::ThreadSafe.select(fds, nil, fds, 0.5)
        begin
          user_output.print(shell_read(-1, 0))
          if sd
            run_single((user_input.gets || '').chomp("\n"))
          end
        rescue WinRM::WinRMWSManFault => e
          print_error(e.fault_description)
          shell_close
        end
        Thread.pass
      end
    end

    def on_registered
      adapter.framework = framework
    end

    # Callback used by the background thread to let us know the shell is done.
    def shell_ended(reason = '')
      self.interacting = false
      framework.events.on_session_interact_completed
      framework.sessions.deregister(self, reason)
    end

    protected

    attr_accessor :shell, :adapter

    def _suspend
      # PSRP does not provide a way to send Ctrl+Z to a foreground process. If
      # the SUB byte is submitted as a new pipeline, WinRM can return a fault
      # that contains invalid XML and closes the session.
      self.interacting = false if prompt_yesno("Background session #{name}?")
    end

  end
end
