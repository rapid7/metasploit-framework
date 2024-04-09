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
    end
  end

end
