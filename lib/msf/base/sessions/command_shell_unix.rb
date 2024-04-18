module Msf::Sessions

  class CommandShellUnix < CommandShell
    def initialize(*args)
      self.platform = "unix"
      super
    end

    def shell_command_token(cmd,timeout = 10)
      shell_command_token_unix(cmd,timeout)
    end

    # Convert the executable and argument array to a command that can be run in this command shell
    # @param executable [String] The process to launch
    # @param args [Array<String>] The arguments to the process
    def to_cmd(executable, args)
      self.class.to_cmd(executable, args)
    end

    # Convert the executable and argument array to a command that can be run in this command shell
    # @param executable [String] The process to launch, or nil if only processing arguments
    # @param args [Array<String>] The arguments to the process
    def self.to_cmd(executable, args)
      quote_requiring = ['\\', '`', '(', ')', '<', '>', '&', '|', ' ', '@', '"', '$', ';']

      if executable.nil?
        cmd_and_args = args
      else
        cmd_and_args = [executable] + args
      end

      escaped = cmd_and_args.map do |arg|
        result = CommandShell._glue_cmdline_escape(arg, quote_requiring, "'", "\\'", "'")
        if result == ''
          result = "''"
        end

        result
      end

      escaped.join(' ')
    end
  end

end
