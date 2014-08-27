
require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # I don't want to raise RuntimeError to be able to abort login
      class GlassfishError < StandardError
      end

      class Glassfish < HTTP

        DEFAULT_PORT  = 4848
        PRIVATE_TYPES = [ :password ]

        # Set the Glassfish version
        attr_accessor :version

        # Session ID needs to be actively tracked
        attr_accessor :jsession

        # Our own Rex HTTP client needs this information
        attr_accessor :ssl

        # Our own Rex HTTP client needs this information
        attr_accessor :ssl_version


        def set_sane_defaults
          super
          self.ssl = false
          self.ssl_version = 'TLS1'
        end


        #
        # Sends a HTTP request with Rex
        # attempt_login is handling all the possible exceptions Rex might raise
        #
        def send_request(opts)
          cli = Rex::Proto::Http::Client.new(host, port, {}, self.ssl, self.ssl_version)
          cli.connect
          req = cli.request_raw(opts)
          res = cli.send_recv(req)

          # Found a cookie? Set it. We're going to need it.
          if res and res.get_cookies =~ /JSESSIONID=(\w*);/i
            self.jsession = $1
          end

          res
        end


        #
        # Starting Glassfish 4, by default bruteforce doesn't work because Secure Admin is disabled,
        # which means nobody can login remotely. You will only find out about this when you try to
        # login, so this should be called during the login process
        #
        def is_secure_admin_disabled?(res)
          return (res.body =~ /Secure Admin must be enabled/i) ? true : false
        end


        #
        # Sends a login request
        #
        def try_login(credential)
          data  = "j_username=#{Rex::Text.uri_encode(credential.public)}&"
          data << "j_password=#{Rex::Text.uri_encode(credential.private)}&"
          data << 'loginButton=Login'

          opts = {
            'uri'     => '/j_security_check',
            'method'  => 'POST',
            'data'    => data,
            'headers' => {
              'Content-Type'   => 'application/x-www-form-urlencoded',
              'Cookie'         => "JSESSIONID=#{self.jsession}",
            }
          }

          res = send_request(opts)

          if is_secure_admin_disabled?(res)
            # Using the exact error message Glassfish says, that way the user can google what
            # it's about.
            raise GlassfishError, "Secure Admin must be enabled to access the DAS remotely."
          end

          res
        end


        #
        # Tries to login to Glassfish version 2
        #
        def try_glassfish_2(credential)
          res = try_login(credential)
          if res and res.code == 302
            opts = {
              'uri'     => '/applications/upload.jsf',
              'method'  => 'GET',
              'headers' => {
                'Cookie'  => "JSESSIONID=#{self.jsession}"
              }
            }
            res = send_request(opts)
            p = /<title>Deploy Enterprise Applications\/Modules/
            if (res and res.code.to_i == 200 and res.body.match(p) != nil)
              return {:status => Metasploit::Model::Login::Status::SUCCESSFUL, :proof => res.body}
            end
          end

          {:status => Metasploit::Model::Login::Status::INCORRECT, :proof => res.body}
        end


        #
        # Tries to login to Glassfish version 3 or 4 (as of now it's the latest)
        #
        def try_glassfish_3(credential)
          res = try_login(credential)
          if res and res.code == 302
            opts = {
              'uri'     => '/common/applications/uploadFrame.jsf',
              'method'  => 'GET',
              'headers' => {
                'Cookie'  => "JSESSIONID=#{self.jsession}"
              }
            }
            res = send_request(opts)

            p = /<title>Deploy Applications or Modules/
            if (res and res.code.to_i == 200 and res.body.match(p) != nil)
              return {:status => Metasploit::Model::Login::Status::SUCCESSFUL, :proof => res.body}
            end
          elsif res and res.code == 400
            raise GlassfishError, "400: Bad HTTP request from try_login"
          end

          {:status => Metasploit::Model::Login::Status::INCORRECT, :proof => res.body}
        end


        #
        # Decides which login routine and returns the results
        #
        def attempt_login(credential)
          result_opts = { credential: credential }

          begin
            case self.version
            when /^[29]\.x$/
              status = try_glassfish_2(credential)
              result_opts.merge!(status: status[:status], proof:status[:proof])
            when /^[34]\./
              status = try_glassfish_3(credential)
              result_opts.merge!(status: status[:status], proof:status[:proof])
           else
              raise GlassfishError, "Glassfish version '#{self.version}' not supported"
            end
          rescue ::EOFError, Rex::ConnectionError, ::Timeout::Error
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
          end

          Result.new(result_opts)
        end

      end
    end
  end
end

