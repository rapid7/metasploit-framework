require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      class PhpMyAdmin < HTTP
        DEFAULT_PORT  = 4848
        PRIVATE_TYPES = [ :password ]
        LOGIN_STATUS = Metasploit::Model::Login::Status # shorter name

        # @!attribute php_my_admin
        #   @return [String] cookie pma à mettre dans la prochaine requete
        attr_accessor :php_my_admin

        # @!attribute token
        #   @return [String] token requete
        attr_accessor :token

        # @!attribute pmaUser_1
        #   @return [String] pmaUser-1 cookie a mettre dans la requete
        attr_accessor :pmaUser_1

        # @!attribute pmaPass_1
        #   @return [String] pmaPass-1 cookie a mettre dans la requete
        attr_accessor :pmaPass_1

        # (see Base#check_setup)
        def check_setup
          begin
            res = send_request({'uri' => uri})
            return "Connection failed" if res.nil?
            if !([200, 302].include?(res.code))
              return "Unexpected HTTP response code #{res.code} (is this really phpMyAdmin ?)"
            end

          rescue ::EOFError, Errno::ETIMEDOUT, Rex::ConnectionError, ::Timeout::Error
            return "Unable to connect to target"
          end

          true
        end

        # Sends a HTTP request with Rex
        #
        # @param (see Rex::Proto::Http::Resquest#request_raw)
        # @return [Rex::Proto::Http::Response] The HTTP response
        def send_request(opts)
          cli = Rex::Proto::Http::Client.new(host, port, {'Msf' => framework, 'MsfExploit' => framework_module}, ssl, ssl_version, proxies)
          configure_http_client(cli)
          cli.connect
          req = cli.request_raw(opts)
          res = cli.send_recv(req)

          # Found a cookie? Set it. We're going to need it.
          if self.php_my_admin == '' && res && res.get_cookies =~ /(phpMyAdmin=[a-z0-9]+;)/i
            self.php_my_admin = res.get_cookies.match(/ (phpMyAdmin=[a-z0-9]+;)/)[1]
          end
          if self.pmaPass_1 == '' && res && res.get_cookies =~ /(pmaPass-1=[a-zA-Z0-9%]+;)/i
            self.pmaPass_1 = $1
          end
          if self.pmaUser_1 == '' && res && res.get_cookies =~ /(pmaUser-1=[a-zA-Z0-9%]+;)/i
            self.pmaUser_1 = $1
          end
          if self.token == ''
            tokens = res.body.match(/<input type="hidden" name="token" value="(\w+)"/)
            self.token = (tokens.nil?) ? '' : tokens[-1]
          end

          res
        end


        # Sends a login request
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Rex::Proto::Http::Response] The HTTP auth response
        def do_login(username, password)
          # on recupere les cookies/token
          send_request({'uri' => "#{uri}index.php"})

          data  = "pma_username=#{username}&"
          data << "pma_password=#{password}&"
          data << "token=#{self.token}"

          opts = {
            'uri'     => "#{uri}index.php",
            'method'  => 'POST',
            'data'    => data,
            'headers' => {
              'Content-Type'   => 'application/x-www-form-urlencoded',
              'Cookie'         => "#{self.pmaUser_1} #{self.php_my_admin}",
            }
          }

          res = send_request(opts)
          if is_logged_in
            return {:status => LOGIN_STATUS::SUCCESSFUL, :proof => self.pmaPass_1}
          end

          return {:status => LOGIN_STATUS::INCORRECT, :proof => res.to_s}

        end


        def is_logged_in
          url_verif = "#{uri}index.php?token=#{self.token}"

          cookies = "#{self.pmaPass_1} #{self.pmaUser_1} #{self.php_my_admin}"

          res = send_request({
            'uri'    => url_verif,
             'headers' => {
               'Content-Type'   => 'application/x-www-form-urlencoded',
               'Cookie'  => cookies
             }
          })

          return (res.body.include? 'Log out')
        end


        # Attemps to login to the server.
        #
        # @param [Metasploit::Framework::Credential] credential The credential information.
        # @return [Result] A Result object indicating success or failure
        def attempt_login(credential)
          # Default Result
          result_opts = {
            credential: credential,
            status: Metasploit::Model::Login::Status::INCORRECT,
            proof: nil,
            host: host,
            port: port,
            protocol: 'tcp'
          }

          self.php_my_admin = ''
          self.pmaUser_1 = ''
          self.pmaPass_1 = ''
          self.token = ''
          # Merge login result
          begin
            result_opts.merge!(do_login(credential.public, credential.private))
          rescue ::Rex::ConnectionError => e
            # Something went wrong during login. 'e' knows what's up.
            result_opts.merge!(status: LOGIN_STATUS::UNABLE_TO_CONNECT, proof: e.message)
          end

          # Return the Result object
          return Result.new(result_opts)
        end

      end
    end
  end
end

