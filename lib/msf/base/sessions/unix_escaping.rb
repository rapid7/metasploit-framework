module Msf::Sessions
  module UnixEscaping
    def shell_command_token(cmd,timeout = 10)
      shell_command_token_unix(cmd,timeout)
    end

    # Convert the executable and argument array to a command that can be run in this command shell
    # @param cmd_and_args [Array<String>] The process path and the arguments to the process
    def to_cmd(cmd_and_args)
      escaped = cmd_and_args.map { |arg| escape_arg(arg) }

      escaped.join(' ')
    end

    # Escape an individual argument per Unix shell rules
    # @param arg [String] Shell argument
    def escape_arg(arg)
      quote_requiring = ['\\', '`', '(', ')', '<', '>', '&', '|', ' ', '@', '"', '$', ';']
      result = CommandShell._glue_cmdline_escape(arg, quote_requiring, "'", "\\'", "'")
      if result == ''
        result = "''"
      end

      result
    end
  end
end