# -*- coding: binary -*-

module Msf
  class Exploit
    class Remote
      module HTTP
        # This module provides a way of interacting with Webmin
        module Webmin
          include Msf::Exploit::Remote::HttpClient
          include Msf::Exploit::Remote::HTTP::Webmin::Login
          include Msf::Exploit::Remote::HTTP::Webmin::Check

          def initialize(info = {})
            super

            register_options(
              [
                Msf::OptString.new('TARGETURI', [true, 'The base path to the Webmin installation', '']),
                Msf::OptString.new('USERNAME', [false, 'Username to authenticate with', 'admin']),
                Msf::OptString.new('PASSWORD', [false, 'Password to authenticate with', nil])
              ], Msf::Exploit::Remote::HTTP::Webmin
            )
          end
        end
      end
    end
  end
end
