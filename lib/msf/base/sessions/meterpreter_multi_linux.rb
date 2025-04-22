# -*- coding: binary -*-

module Msf
  module Sessions
    ###
    #
    # This class creates a platform-specific, architecture agnostic meterpreter session type
    #
    ###
    class MeterpreterMultiLinux < Msf::Sessions::Meterpreter
      def supports_ssl?
        false
      end

      def supports_zlib?
        false
      end

      def initialize(rstream, opts = {})
        super
        self.base_platform = 'linux'
        self.base_arch = ARCH_ANY # will be populated automatically
      end
    end
  end
end
