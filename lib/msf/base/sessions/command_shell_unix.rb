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
      always_quote = /[']/
      always_escape = /([$"])/
      escape_if_not_quoted = /([\\`\(\)<>&| ])/

      if executable.nil?
        cmd_and_args = args
      else
        cmd_and_args = [executable] + args
      end

      escaped = cmd_and_args.map do |arg|
        needs_quoting = false
        if arg.match(always_quote)
          needs_quoting = true
        else
          arg = arg.gsub(escape_if_not_quoted, "\\\\\\1")
        end
        arg = arg.gsub(always_escape, "\\\\\\1")

        # Do this at the end, so we don't get confused between the double-quotes we're escaping, and the ones we're using to wrap.
        if needs_quoting
          arg = "\"#{arg}\""
        end

        arg
      end

      escaped.join(' ')
    end
  end

end
