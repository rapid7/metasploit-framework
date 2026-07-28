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
            OptArray.new(
              'AutoLoadExtensions',
              [true, "Automatically load extensions on bootstrap.", ['priv', 'stdapi']]
            )
          ],
          self.class
        )
      end
    end
  end
end
