module Msf::Sessions

  class CommandShellWindows < CommandShell
    def initialize(*args)
      self.platform = "windows"
      super
    end

    include Msf::Sessions::WindowsEscaping
    extend Msf::Sessions::WindowsEscaping
  end
end
