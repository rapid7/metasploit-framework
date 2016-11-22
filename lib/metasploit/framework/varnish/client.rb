# -*- coding: binary -*-
require 'msf/core'
require 'msf/core/exploit/tcp'

module Metasploit
  module Framework
    module Varnish
      module Client


        def login(pass)
          begin
            if require_auth?
              sock.put("auth #{Rex::Text.rand_text_alphanumeric(3)}\n") # Cause a login fail to get the challenge
              res = sock.get_once(-1,3) # grab challenge
              if res && res =~ /107 \d+\s\s\s\s\s\s\n(\w+)\n\nAuthentication required./ # 107 auth
                challenge = $1
                response = challenge + "\n"
                response << pass + "\n"
                response << challenge + "\n"
                response = Digest::SHA256.hexdigest(response)
                sock.put("auth #{response}\n")
                res = sock.get_once(-1,3)
                if res && res =~ /200 \d+/ # 200 ok
                  return true
                else
                  return false
                end
              else
                raise RuntimeError, "Varnish Login timeout"
              end
            end
          rescue Timeout::Error
            raise RuntimeError, "Varnish Login timeout"
          end
        end

        def close_session
          sock.put('quit')
        end
        
        def require_auth?
          sock.put("auth #{Rex::Text.rand_text_alphanumeric(3)}\n") # Cause a login fail to get the challenge
          res = sock.get_once(-1,3) # grab challenge
            if res && res =~ /107 \d+\s\s\s\s\s\s\n(\w+)\n\nAuthentication required./ # 107 auth
              return true
            else
              return false
            end
        end

      end
    end
  end
end

