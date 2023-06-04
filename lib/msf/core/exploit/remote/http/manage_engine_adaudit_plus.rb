module Msf
  class Exploit
    class Remote
      module HTTP
        # This module provides a way of interacting with ManageEngine ADAudit Plus installations
        module ManageEngineAdauditPlus
          include Msf::Exploit::Remote::HttpClient
          include Msf::Exploit::Remote::HTTP::ManageEngineAdauditPlus::JsonPostData
          include Msf::Exploit::Remote::HTTP::ManageEngineAdauditPlus::Login
          include Msf::Exploit::Remote::HTTP::ManageEngineAdauditPlus::StatusCodes
          include Msf::Exploit::Remote::HTTP::ManageEngineAdauditPlus::TargetInfo
          include Msf::Exploit::Remote::HTTP::ManageEngineAdauditPlus::URIs

          def initialize(info = {})
            super

            register_options(
              [
                Msf::OptString.new('TARGETURI', [true, 'The base path to the ManageEngine ADAudit Plus application', '/']),
                Msf::OptString.new('USERNAME', [false, 'Username to authenticate with', 'admin']),
                Msf::OptString.new('PASSWORD', [false, 'Password to authenticate with', 'admin']),

              ], Msf::Exploit::Remote::HTTP::ManageEngineAdauditPlus
            )
          end
        end
      end
    end
  end
end
