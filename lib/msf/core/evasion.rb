require 'msf/core/module'

module Msf
  class Evasion < Msf::Module

    class Failed < RuntimeError ; end

    def self.type
      Msf::MODULE_EVASION
    end

    def type
      Msf::MODULE_EVASION
    end

    def setup
    end

    def run
    end

    def fail_with(reason, msg=nil)
      raise Msf::Evasion::Failed, "#{reason}: #{msg}"
    end

    def evasion_commands
      {}
    end
  end
end