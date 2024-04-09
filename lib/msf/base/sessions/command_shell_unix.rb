module Msf::Sessions

  class CommandShellUnix < CommandShell

    module Mixin
      # Convert the executable and argument array to a command that can be run in this command shell
      # @param executable [String] The process to launch
      # @param args [Array<String>] The arguments to the process
      def to_cmd(executable, args)
        needs_escaping = "'"
        chars_need_quoting = ['"', '\\', '$', '`', '(', ')', ' ', '<', '>', '&', '|']
        cmd_and_args = [executable] + args
        escaped = cmd_and_args.map do |arg|
          needs_quoting = chars_need_quoting.any? do |char|
            arg.include?(char)
          end

          arg = arg.gsub("'", "\\\\'")
          if needs_quoting
            arg = "'#{arg}'"
          end

          arg
        end

        escaped.join(' ')
      end
    end

    include Mixin

    def initialize(*args)
      self.platform = "unix"
      super
    end

    def shell_command_token(cmd,timeout = 10)
      shell_command_token_unix(cmd,timeout)
    end
  end

end
