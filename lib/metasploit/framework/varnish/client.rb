# -*- coding: binary -*-
require 'msf/core'
require 'msf/core/exploit/tcp'

module Metasploit
  module Framework
    module Varnish
      module Client

        @AUTH_REQUIRED_REGEX = /107 \d+\s\s\s\s\s\s\n(\w+)\n\nAuthentication required\./ # 107 auth
        @AUTH_SUCCESS_REGEX = /200 \d+/ # 200 ok

        def login(pass)
          # based on https://www.varnish-cache.org/trac/wiki/CLI
          begin
            auth = require_auth?
            if not !!auth
              #raise RuntimeError, $1 + "\n" + pass.strip + "\n" + $1 + "\n" + "auth " + Digest::SHA256.hexdigest("#{$1}\n#{pass.strip}\n#{$1}\n")
              response = Digest::SHA256.hexdigest("#{$1}\n#{pass.strip}\n#{$1}\n")
              sock.put("auth #{response}\n")
              res = sock.get_once(-1,3)
              raise RuntimeError, res
              if res && res =~ @AUTH_SUCCESS_REGEX
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
        
        def require_auth?
          # function returns false if no auth is required, else
          sock.put("auth #{Rex::Text.rand_text_alphanumeric(3)}\n") # Cause a login fail to get the challenge
          res = sock.get_once(-1,3) # grab challenge
          if res && res =~ @AUTH_REQUIRED_REGEX
            return $1
          end
          return false
        end

      end
    end
  end
end

