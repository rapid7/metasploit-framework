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

      def create_proc
        # We use cmd rather than powershell because powershell v3 on 2012 (and maybe earlier)
        # do not seem to pass us stdout/stderr.
        self.command_id = send_command('cmd.exe', [])
      end

      def with_command_shell(input, _arguments = [])
        tries ||= 2
        send_stdin(input)
        yield shell_id, command_id
      rescue WinRM::WinRMWSManFault => e
        raise unless FAULTS_FOR_RESET.include?(e.fault_code) && (tries -= 1) > 0

        reset_on_error(e)
        retry
      end

      def cleanup_shell
        cleanup_command(command_id)
      end

      # Runs the specified command with optional arguments
      # @param block [&block] The optional callback for any realtime output
      # @yieldparam [string] standard out response text
      # @yieldparam [string] standard error response text
      # @yieldreturn [WinRM::Output] The command output
      def read_stdout(&block)
        open unless shell_id
        create_proc unless command_id
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

      def send_ctrl_c
        open unless shell_id
        create_proc unless command_id

        ctrl_c_msg = CtrlC.new(
          connection_opts,
          shell_uri: shell_uri,
          shell_id: shell_id,
          command_id: command_id
        )
        transport.send_request(ctrl_c_msg.build)
      end

      def send_stdin(input)
        open unless shell_id
        create_proc unless command_id

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
        self.owner = REXML::XPath.first(resp_doc, '//rsp:Owner').text
        REXML::XPath.first(resp_doc, "//*[@Name='ShellId']").text
      end

      attr_accessor :owner

      protected

      attr_accessor :command_id
    end
  end
end
