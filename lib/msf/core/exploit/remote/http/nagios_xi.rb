# -*- coding: binary -*-

module Msf
  class Exploit
    class Remote
      module HTTP
        # This module provides a way of interacting with Nagios XI installations
        module NagiosXi
          include Msf::Exploit::Remote::HttpClient
          include Msf::Exploit::Remote::HTTP::NagiosXi::Install
          include Msf::Exploit::Remote::HTTP::NagiosXi::Login
          include Msf::Exploit::Remote::HTTP::NagiosXi::RceCheck
          include Msf::Exploit::Remote::HTTP::NagiosXi::URIs
          include Msf::Exploit::Remote::HTTP::NagiosXi::Version

          def initialize(info = {})
            super

            register_options(
              [
                Msf::OptString.new('TARGETURI', [true, 'The base path to the Nagios XI application', '/nagiosxi/']),
                Msf::OptString.new('USERNAME', [false, 'Username to authenticate with', 'nagiosadmin']),
                Msf::OptString.new('PASSWORD', [false, 'Password to authenticate with', nil]),
                Msf::OptBool.new('FINISH_INSTALL', [false, 'If the Nagios XI installation has not been completed, try to do so. This includes signing the license agreement.', false])

              ], Msf::Exploit::Remote::HTTP::NagiosXi
            )
          end
        end
      end
    end
  end
end
