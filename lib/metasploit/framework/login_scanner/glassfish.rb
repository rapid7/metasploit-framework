
require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # The Glassfish HTTP LoginScanner class provides methods to do login routines
      # for Glassfish 2, 3 and 4.
      class Glassfish < HTTP

        DEFAULT_PORT  = 4848
        PRIVATE_TYPES = [ :password ]

        # @!attribute [r] version
        #   @return [String] Glassfish version
        attr_accessor :version

        # @!attribute jsession
        #   @return [String] Cookie session
        attr_accessor :jsession

        # @!attribute http_username
        attr_accessor :http_username
        #   @return [String] HTTP username

        # @!attribute http_password
        attr_accessor :http_password

        # (see Base#check_setup)
        def check_setup
          begin
            res = send_request({'uri' => '/common/index.jsf'})
            return "Connection failed" if res.nil?
            if !([200, 302].include?(res.code))
              return "Unexpected HTTP response code #{res.code} (is this really Glassfish?)"
            end

            # If remote login is enabled on 4.x, it redirects to https on the
            # same port.
            if !self.ssl && res.headers['Location'] =~ /^https:/
              self.ssl = true
              res = send_request({'uri' => '/common/index.jsf'})
              if res.nil?
                return "Connection failed after SSL redirection"
              end
              if res.code != 200
                return "Unexpected HTTP response code #{res.code} after SSL redirection (is this really Glassfish?)"
              end
            end

            res = send_request({'uri' => '/login.jsf'})
            return "Connection failed" if res.nil?
            extract_version(res.headers['Server'])

            if @version.nil? || @version !~ /^[2349]/
              return "Unsupported version ('#{@version}')"
            end
          rescue ::EOFError, Errno::ETIMEDOUT, Rex::ConnectionError, ::Timeout::Error
            return "Unable to connect to target"
          end

          false
        end

        # Sends a HTTP request with Rex
        #
        # @param (see Rex::Proto::Http::Resquest#request_raw)
        # @return [Rex::Proto::Http::Response] The HTTP response
        def send_request(opts)
          cli = Rex::Proto::Http::Client.new(host, port, {'Msf' => framework, 'MsfExploit' => framework_module}, ssl, ssl_version, proxies, http_username, http_password)
          configure_http_client(cli)
          cli.connect
          req = cli.request_raw(opts)
          res = cli.send_recv(req)

          # Found a cookie? Set it. We're going to need it.
          if res && res.get_cookies =~ /JSESSIONID=(\w*);/i
            self.jsession = $1
          end

          res
        end


        # As of Sep 2014, if Secure Admin is disabled, it simply means the admin isn't allowed
        # to login remotely. However, the authentication will still run and hint whether the
        # password is correct or not.
        #
        # @param res [Rex::Proto::Http::Response] The HTTP auth response
        # @return [boolean] True if disabled, otherwise false
        def is_secure_admin_disabled?(res)
          return (res.body =~ /Secure Admin must be enabled/i) ? true : false
        end


        # Sends a login request
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Rex::Proto::Http::Response] The HTTP auth response
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

          send_request(opts)
        end


        # Tries to login to Glassfish version 2
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Hash]
        #   * :status [Metasploit::Model::Login::Status]
        #   * :proof [String] the HTTP response body
        def try_glassfish_2(credential)
          res = try_login(credential)
          if res && res.code == 302
            opts = {
              'uri'     => '/applications/upload.jsf',
              'method'  => 'GET',
              'headers' => {
                'Cookie'  => "JSESSIONID=#{self.jsession}"
              }
            }
            res = send_request(opts)
            p = /<title>Deploy Enterprise Applications\/Modules/
            if (res && res.code.to_i == 200 && res.body.match(p) != nil)
              return {:status => Metasploit::Model::Login::Status::SUCCESSFUL, :proof => res.body}
            end
          end

          {:status => Metasploit::Model::Login::Status::INCORRECT, :proof => res.body}
        end


        # Tries to login to Glassfish version 9
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Hash]
        #   * :status [Metasploit::Model::Login::Status]
        #   * :proof [String] the HTTP response body
        def try_glassfish_9(credential)
          res = try_login(credential)

          if res && res.code.to_i == 302 && res.headers['Location'].to_s !~ /loginError\.jsf$/
            return {:status => Metasploit::Model::Login::Status::SUCCESSFUL, :proof => res.body}
          end

          {:status => Metasploit::Model::Login::Status::INCORRECT, :proof => res.body}
        end


        # Tries to login to Glassfish version 3 or 4 (as of now it's the latest)
        #
        # @param (see #try_glassfish_2)
        # @return (see #try_glassfish_2)
        def try_glassfish_3(credential)
          res = try_login(credential)
          if res && res.code == 302
            opts = {
              'uri'     => '/common/applications/uploadFrame.jsf',
              'method'  => 'GET',
              'headers' => {
                'Cookie'  => "JSESSIONID=#{self.jsession}"
              }
            }
            res = send_request(opts)

            p = /<title>Deploy Applications or Modules/
            if (res && res.code.to_i == 200 && res.body.match(p) != nil)
              return {:status => Metasploit::Model::Login::Status::SUCCESSFUL, :proof => res.body}
            end
          elsif res && is_secure_admin_disabled?(res)
            return {:status => Metasploit::Model::Login::Status::DENIED_ACCESS, :proof => res.body}
          elsif res && res.code == 400
            return {:status => Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, :proof => res.body}
          end

          {:status => Metasploit::Model::Login::Status::INCORRECT, :proof => res.body}
        end


        # Decides which login routine and returns the results
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Result]
        def attempt_login(credential)
          result_opts = { credential: credential }

          begin
            case self.version
            when /^2\.x$/
              status = try_glassfish_2(credential)
              result_opts.merge!(status)
            when /^[34]\./
              status = try_glassfish_3(credential)
              result_opts.merge!(status)
            when /^9\.x$/
              status = try_glassfish_9(credential)
              result_opts.merge!(status) 
            end
          rescue ::EOFError, Errno::ECONNRESET, Rex::ConnectionError, OpenSSL::SSL::SSLError, ::Timeout::Error => e
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
          end

          Result.new(result_opts)
        end


        # Extract the target's glassfish version from the HTTP Server Sun Java System Application Server 9.1header
        # (ex: Sun Java System Application Server 9.x)
        #
        # @param banner [String] `Server` header from a Glassfish service response
        # @return [String] version string, e.g. '2.x'
        # @return [nil] If the banner did not match any of the expected values
        def extract_version(banner)
          # Set version.  Some GlassFish servers return banner "GlassFish v3".
          if banner =~ /(GlassFish Server|Open Source Edition)[[:blank:]]*(\d\.\d)/
            @version = $2
          elsif banner =~ /GlassFish v(\d)/
            @version = $1
          elsif banner =~ /Sun GlassFish Enterprise Server v2/
            @version = '2.x'
          elsif banner =~ /Sun Java System Application Server 9/
            @version = '9.x'
          else
            @version = nil
          end

          return @version
        end


      end
    end
  end
end

