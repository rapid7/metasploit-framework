require 'msf/core/module'

module Msf
  class Evasion < Msf::Module

    class Complete < RuntimeError ; end

    class Failed < RuntimeError ; end

    def initialize(info={})
      if (info['Payload'] and info['Payload']['Compat'])
        info['Compat'] = Hash.new if (info['Compat'] == nil)
        info['Compat']['Payload'] = Hash.new if (info['Compat']['Payload'] == nil)
        info['Compat']['Payload'].update(info['Payload']['Compat'])
      end

      super(info)

      self.payload_info = info['Payload'] || {}

      if (info['Payload'] and info['Payload']['ActiveTimeout'])
        self.active_timeout = info['Payload']['ActiveTimeout'].to_i
      end


    end

    def self.type
      Msf::MODULE_EVASION
    end

    def type
      Msf::MODULE_EVASION
    end

    def setup
    end

    def is_payload_compatible?(name)
      p = framework.payloads[name]

      pi = p.new

      # Are we compatible in terms of conventions and connections and
      # what not?
      return false if !compatible?(pi)

      # If the payload is privileged but the exploit does not give
      # privileged access, then fail it.
      return false if !self.privileged && pi.privileged

      return true
    end

    def compatible_payloads
      payloads = []

      framework.payloads.each_module(
        'Arch' => arch, 'Platform' => platform) { |name, mod|
        payloads << [ name, mod ] if is_payload_compatible?(name)
      }

      return payloads
    end

    def run
      raise NotImplementedError
    end

    def cleanup
    end

    def fail_with(reason, msg=nil)
      raise Msf::Evasion::Failed, "#{reason}: #{msg}"
    end

    def evasion_commands
      {}
    end

    attr_reader :payload_info

    attr_accessor :payload_info

    attr_reader :payload
  end
end