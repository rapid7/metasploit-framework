# -*- coding: binary -*-

module Msf
  class Exploit
    class Remote
      module HTTP
        # This module provides a way of interacting with moodle installations
        module Moodle
          include Msf::Exploit::Remote::HttpClient
          include Msf::Exploit::Remote::HTTP::Moodle::Base
          include Msf::Exploit::Remote::HTTP::Moodle::Version
          include Msf::Exploit::Remote::HTTP::Moodle::URIs
          include Msf::Exploit::Remote::HTTP::Moodle::Helpers
          include Msf::Exploit::Remote::HTTP::Moodle::Login
          include Msf::Exploit::Remote::HTTP::Moodle::Course
          include Msf::Exploit::Remote::HTTP::Moodle::Admin

          def initialize(info = {})
            super

            register_options(
              [
                Msf::OptString.new('TARGETURI', [true, 'The base path to the moodle application', '/'])
              ], Msf::Exploit::Remote::HTTP::Moodle
            )

            register_advanced_options(
              [
                Msf::OptBool.new('MOODLECHECK', [true, 'Check if the website is a valid Moodle install', true]),
              ], Msf::Exploit::Remote::HTTP::Moodle
            )
          end
        end
      end
    end
  end
end
