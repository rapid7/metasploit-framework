# -*- coding: binary -*-

module Msf
  class Exploit
    class Remote
      module HTTP
        # This module provides a way of interacting with typo3 installations
        module Typo3
          require 'msf/core/exploit/http/typo3/login'
          require 'msf/core/exploit/http/typo3/uris'

          include Msf::Exploit::Remote::HttpClient
          include Msf::Exploit::Remote::HTTP::Typo3::Login
          include Msf::Exploit::Remote::HTTP::Typo3::URIs

          def initialize(info = {})
            super

            register_options(
              [
                Msf::OptString.new('TARGETURI', [true, 'The base path to the typo3 application', '/']),
              ], Msf::Exploit::Remote::HTTP::Typo3
            )
          end
        end
      end
    end
  end
end
