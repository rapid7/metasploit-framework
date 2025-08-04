# -*- coding: binary -*-

require 'shellwords'

module Msf
  module Sessions
    #
    # Defines common options across all Meterpreter implementations
    #
    module MeterpreterOptions::Windows
      include Msf::Sessions::MeterpreterOptions::Common
      def initialize(info = {})
        super(info)

        register_advanced_options(
          [
            OptString.new(
              'AutoLoadExtensions',
              [true, "Automatically load extensions on bootstrap, semicolon separated.", 'unhook,priv,stdapi']
            ),
            OptBool.new(
              'AutoUnhookProcess',
              [true, "Automatically load the unhook extension and unhook the process", false]
            ),
          ],
          self.class
        )
      end
    end
  end
end
