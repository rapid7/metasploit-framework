# -*- coding: binary -*-

require 'shellwords'

module Msf
  module Sessions
    #
    # Defines common options across all Meterpreter implementations
    #
    module MeterpreterOptions::Android
      include Msf::Sessions::MeterpreterOptions::Common
      def initialize(info = {})
        super(info)

        register_advanced_options(
          [
            OptString.new(
              'AutoLoadExtensions',
              [true, "Automatically load extensions on bootstrap, semicolon separated.", 'stdapi,android']
            ),
          ],
          self.class
        )
      end
    end
  end
end
