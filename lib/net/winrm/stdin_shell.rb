require 'winrm'
require 'winrm/wsmv/write_stdin'
require 'net/winrm/ctrl_c'
require 'net/winrm/receive_response_reader'

module Net
  module MsfWinRM
    # WinRM shell to use stdin, rather than sending isolated commands
    class StdinShell < WinRM::Shells::Cmd
      # We create our own empty finalizers because the built-in one triggers a
      # request using the Rex HTTP client, which segfaults; possibly because it
      # creates a thread, or something else that is not allowed in a finalizer.
      # In this situation (observed only when the user quits MSF with active sessions),
      # we'll just let the shell continue.
      def remove_finalizer; end

      def add_finalizer; end

      def send_command(command, arguments = [])
        open unless shell_id
        super(command, arguments)
      end

      # Runs a shell command synchronously, and returns the output
      def shell_command_synchronous(command, args, timeout)
        start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC, :millisecond)
        command_id = send_command(command, args)
        buffer = []
        begin
          while (Process.clock_gettime(Process::CLOCK_MONOTONIC, :millisecond) - start_time) < (timeout * 1000)
            read_stdout(command_id) do |stdout, stderr|
              buffer << stdout if stdout
              buffer << stderr if stderr
            end
          end
        rescue EOFError
          # Shell terminated of its own accord
        ensure
          cleanup_command(command_id)
        end
        buffer.join('')
      end

      # Runs the specified command with optional arguments
      # @param block [&block] The optional callback for any realtime output
      # @yieldparam [string] standard out response text
      # @yieldparam [string] standard error response text
      # @yieldreturn [WinRM::Output] The command output
      def read_stdout(command_id, &block)
        open unless shell_id
        begin
          response_reader.read_output(command_output_message(shell_id, command_id), &block)
        rescue WinRM::WinRMWSManFault => e
          # If no output is available before the wsman:OperationTimeout expires,
          # the server MUST return a WSManFault with the Code attribute equal to
          # 2150858793. When the client receives this fault, it SHOULD issue
          # another Receive request.
          # http://msdn.microsoft.com/en-us/library/cc251676.aspx
          if e.fault_code == '2150858793'
            yield nil, nil
          else
            raise
          end
        end
      end

      def send_ctrl_c(command_id)
        ctrl_c_msg = CtrlC.new(
          connection_opts,
          shell_uri: shell_uri,
          shell_id: shell_id,
          command_id: command_id
        )
        transport.send_request(ctrl_c_msg.build)
      end

      def send_stdin(input, command_id)
        open unless shell_id

        stdin_msg = WinRM::WSMV::WriteStdin.new(
          connection_opts,
          shell_uri: shell_uri,
          shell_id: shell_id,
          command_id: command_id,
          stdin: input
        )
        result = transport.send_request(stdin_msg.build)
        result
      rescue WinRM::WinRMWSManFault => e
        raise unless [ERROR_OPERATION_ABORTED, SHELL_NOT_FOUND].include?(e.fault_code)
      rescue WinRM::WinRMHTTPTransportError => e
        # dont let the cleanup raise so we dont lose any errors from the command
        logger.info("[WinRM] #{e.status_code} returned in cleanup with error: #{e.message}")
      end

      def response_reader
        @response_reader ||= ReceiveResponseReader.new(transport, logger)
      end

      def open_shell
        msg = WinRM::WSMV::CreateShell.new(connection_opts, shell_opts)
        resp_doc = transport.send_request(msg.build)
        match = REXML::XPath.first(resp_doc, '//rsp:Owner')
        self.owner = match.text if match
        REXML::XPath.first(resp_doc, "//*[@Name='ShellId']").text
      end

      attr_accessor :owner

    end
  end
end
