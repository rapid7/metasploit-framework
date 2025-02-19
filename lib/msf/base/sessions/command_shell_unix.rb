module Msf::Sessions

  class CommandShellUnix < CommandShell
    def initialize(*args)
      self.platform = "unix"
      super
    end

    include Msf::Sessions::UnixEscaping
    extend Msf::Sessions::UnixEscaping
  end

end
