
module Msf::Sessions

  class CommandShellWindows < CommandShell
    def initialize(*args)
      self.platform = "windows"
      super
    end
    def shell_command_token(cmd,timeout = 10)
      shell_command_token_base(cmd,timeout,'&')
    end
  end

end
