# -*- coding: binary -*-

require 'shellwords'

module Msf
  module Sessions
    #
    # Defines common options across all Meterpreter implementations
    #
    module MeterpreterOptions::Python
      include Msf::Sessions::MeterpreterOptions::Common
      def initialize(info = {})
        super(info)

        register_advanced_options(
          [
            OptArray.new(
              'AutoLoadExtensions',
              [true, "Automatically load extensions on bootstrap.", ['stdapi']]
            ),
          ],
          self.class
        )
      end
    end
  end
end
