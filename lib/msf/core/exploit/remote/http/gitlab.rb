# -*- coding: binary -*-

module Msf
  class Exploit
    class Remote
      module HTTP
        # This module provides a way of interacting with gitlab installations
        module Gitlab
          include Msf::Exploit::Remote::HttpClient
          include Msf::Exploit::Remote::HTTP::Gitlab::AccessTokens
          include Msf::Exploit::Remote::HTTP::Gitlab::Authenticate
          include Msf::Exploit::Remote::HTTP::Gitlab::Error
          include Msf::Exploit::Remote::HTTP::Gitlab::Form
          include Msf::Exploit::Remote::HTTP::Gitlab::Groups
          include Msf::Exploit::Remote::HTTP::Gitlab::Helpers
          include Msf::Exploit::Remote::HTTP::Gitlab::Import
          include Msf::Exploit::Remote::HTTP::Gitlab::Rest
          include Msf::Exploit::Remote::HTTP::Gitlab::Version

          def initialize(info = {})
            super

            register_options(
              [
                Msf::OptString.new('TARGETURI', [true, 'The base path to the gitlab application', '/'])
              ], Msf::Exploit::Remote::HTTP::Gitlab
            )
          end

          # class GitLabClientException < StandardError; end
        end
      end
    end
  end
end
