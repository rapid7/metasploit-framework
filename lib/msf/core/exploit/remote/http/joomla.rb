# -*- coding: binary -*-

module Msf
  class Exploit
    class Remote
      module HTTP
        module Joomla
          include Msf::Exploit::Remote::HttpClient
          include Msf::Exploit::Remote::HTTP::Joomla::Base
          include Msf::Exploit::Remote::HTTP::Joomla::Version

          def initialize(info = {})
            super

            register_options(
              [
                Msf::OptString.new('TARGETURI', [true, 'The base path to the Joomla application', '/'])
              ], Msf::Exploit::Remote::HTTP::Joomla
            )
          end

        end
      end
    end
  end
end
