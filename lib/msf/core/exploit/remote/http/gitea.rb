# -*- coding: binary -*-

module Msf
  class Exploit
    class Remote
      module HTTP
        # This module provides a way of interacting with gitea installations
        module Gitea
          include Msf::Exploit::Remote::HttpClient
          include Msf::Exploit::Remote::HTTP::Gitea::Base
          include Msf::Exploit::Remote::HTTP::Gitea::Version
          include Msf::Exploit::Remote::HTTP::Gitea::Helpers
          include Msf::Exploit::Remote::HTTP::Gitea::Login
          include Msf::Exploit::Remote::HTTP::Gitea::Error
          include Msf::Exploit::Remote::HTTP::Gitea::URIs
          include Msf::Exploit::Remote::HTTP::Gitea::Repository

          def initialize(info = {})
            super

            register_options(
              [
                Msf::OptString.new('TARGETURI', [true, 'The base path to the gitea application', '/'])
              ], Msf::Exploit::Remote::HTTP::Gitea
            )

            register_advanced_options(
              [
                Msf::OptBool.new('GITEACHECK', [true, 'Check if the website is a valid Gitea install', true]),
              ], Msf::Exploit::Remote::HTTP::Gitea
            )
          end
        end
      end
    end
  end
end
