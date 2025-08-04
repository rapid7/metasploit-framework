# -*- coding: binary -*-

require 'shellwords'

module Msf
  module Sessions
    #
    # Defines common options across all Meterpreter implementations
    #
    module MeterpreterOptions::Linux
      include Msf::Sessions::MeterpreterOptions::Common
      def initialize(info = {})
        super(info)

        register_advanced_options(
          [
            OptString.new(
              'AutoLoadExtensions',
              [true, "Automatically load extensions on bootstrap, comma separated.", 'stdapi']
            ),
            OptString.new(
              'PayloadProcessCommandLine',
              [ false, 'The displayed command line that will be used by the payload', '']
            ),
          ],
          self.class
        )
      end
    end
  end
end
