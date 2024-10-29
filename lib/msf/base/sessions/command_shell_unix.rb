module Msf::Sessions

  class CommandShellUnix < CommandShell
    def initialize(*args)
      self.platform = "unix"
      super
    end
    def shell_command_token(cmd,timeout = 10)
      shell_command_token_unix(cmd,timeout)
    end
  end

end
