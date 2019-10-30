# -*- coding: binary -*-
require 'msf/core'
require 'msf/core/exploit/tcp'

module Metasploit
  module Framework
    module Varnish
      module Client

        @@AUTH_REQUIRED_REGEX = /107 \d+\s\s\s\s\s\s\n(\w+)\n\nAuthentication required\./ # 107 auth
        @@AUTH_SUCCESS_REGEX = /200 \d+/ # 200 ok

        def require_auth?
          # function returns false if no auth is required, else the challenge string
          res = sock.get_once # varnish can give the challenge on connect, so check if we have it already
          if res && res =~ @@AUTH_REQUIRED_REGEX
            return $1
          end
          # Cause a login fail to get the challenge. Length is correct, but this has upper chars, subtle diff for debugging
          sock.put("auth #{Rex::Text.rand_text_alphanumeric(64)}\n")
          res = sock.get_once # grab challenge
          if res && res =~ @@AUTH_REQUIRED_REGEX
            return $1
          end
          return false
        end

        def login(pass)
          # based on https://www.varnish-cache.org/trac/wiki/CLI
          begin
            challenge = require_auth?
            if !!challenge
              response = Digest::SHA256.hexdigest("#{challenge}\n#{pass.strip}\n#{challenge}\n")
              sock.put("auth #{response}\n")
              res = sock.get_once
              if res && res =~ @@AUTH_SUCCESS_REGEX
                return true
              else
                return false
              end
            else
              raise RuntimeError, "No Auth Required"
            end
          rescue Timeout::Error
            raise RuntimeError, "Varnish Login timeout"
          end
        end

        def close_session
          sock.put('quit')
        end

      end
    end
  end
end

