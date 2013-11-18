# -*- coding: binary -*-

# This module provides a way of interacting with typo3 installations
module Msf
  module HTTP
    module Typo3
      require 'msf/http/typo3/login'
      require 'msf/http/typo3/uris'

      include Msf::Exploit::Remote::HttpClient
      include Msf::HTTP::Typo3::Login
      include Msf::HTTP::Typo3::URIs

      def initialize(info = {})
        super

        register_options(
            [
                Msf::OptString.new('TARGETURI', [true, 'The base path to the typo3 application', '/']),
            ], HTTP::Typo3
        )
      end
    end
  end
end
