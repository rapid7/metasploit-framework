require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      # Ivanti Login Scanner supporting
      # - User Login
      # - Admin Login
      class Ivanti < HTTP

        DEFAULT_SSL_PORT = 443
        LIKELY_PORTS = [443]
        LIKELY_SERVICE_NAMES = [
          'Ivanti Connect Secure'
        ]
        PRIVATE_TYPES = [:password]
        REALM_KEY = nil

        def initialize(scanner_config, admin)
          @admin = admin
          super(scanner_config)
        end

        def check_setup
          request_params = {
            'method' => 'GET',
            'uri' => normalize_uri('/dana-na/auth/url_default/welcome.cgi')
          }

          res = send_request(request_params)

          if res && res.code == 200 && res.body&.include?('Ivanti Connect Secure')
            return false
          end

          'Application might not be Ivanti Connect Secure, please check'
        end

        def create_admin_request(username, password, token, protocol, peer)
          {
            'method' => 'POST',
            'uri' => normalize_uri('/dana-na/auth/url_admin/login.cgi'),
            'ctype' => 'application/x-www-form-urlencoded',
            'headers' =>
            {
              'Origin' => "#{protocol}://#{peer}",
              'Referer' => "#{protocol}://#{peer}/dana-na/auth/url_admin/welcome.cgi"
            },
            'vars_post' => {
              tz_offset: '60',
              xsauth_token: token,
              username: username,
              password: password,
              realm: 'Admin+Users',
              btnSubmit: 'Sign+In'

            },
            'encode_params' => false
          }
        end

        def do_admin_logout(cookies)
          admin_page_res = send_request({ 'method' => 'GET', 'uri' => normalize_uri('/dana-admin/misc/admin.cgi?'), 'cookie' => cookies })
          admin_page_s = admin_page_res.to_s
          re = /xsauth=[a-z0-9]{32}/
          xsauth = re.match(admin_page_s)

          return nil if xsauth.nil?

          send_request({ 'method' => 'GET', 'uri' => normalize_uri('/dana-na/auth/logout.cgi?' + xsauth[0]), 'cookie' => cookies })
        end

        def get_token
          res = send_request({
            'uri' => normalize_uri('/dana-na/auth/url_admin/welcome.cgi')
          })
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unable to connect to the Ivanti service' } if res.nil?

          html_document = res.get_html_document
          html_document.xpath('//input[@id="xsauth_token"]/@value')&.text
        end

        def do_admin_login(username, password)
          token = get_token

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unable to connect to the Ivanti service' } if token.blank?

          protocol = ssl ? 'https' : 'http'
          peer = "#{host}:#{port}"
          admin_req = create_admin_request(username, password, token, protocol, peer)
          begin
            res = send_request(admin_req)
          rescue ::Rex::ConnectionError, ::Rex::ConnectionProxyError, ::Errno::ECONNRESET, ::Errno::EINTR, ::Rex::TimeoutError, ::Timeout::Error, ::EOFError => e
            return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e }
          end
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unable to connect to the Ivanti service' } if res.nil?
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: "Received an unexpected status code: #{res.code}" } if res.code != 302

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unexpected response' } if !res.headers&.key?('location')

          return { status: ::Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.to_s } if res.headers['location'] == '/dana-na/auth/url_admin/welcome.cgi?p=admin%2Dconfirm'

          if res.headers['location'] == '/dana-admin/misc/admin.cgi'
            do_admin_logout(res.get_cookies)
            return { status: ::Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.to_s }
          end

          return { status: ::Metasploit::Model::Login::Status::INCORRECT, proof: res.to_s }
        end

        def create_user_request(username, password, protocol, peer)
          {
            'method' => 'POST',
            'uri' => normalize_uri('/dana-na/auth/url_default/login.cgi'),
            'ctype' => 'application/x-www-form-urlencoded',
            'headers' =>
            {
              'Origin' => "#{protocol}://#{peer}",
              'Referer' => "#{protocol}://#{peer}/dana-na/auth/url_default/welcome.cgi"
            },
            'vars_post' =>
              {
                tz_offset: '',
                win11: '',
                clientMAC: '',
                username: username,
                password: password,
                realm: 'Users',
                btnSubmit: 'Sign+In'
              },
            'encode_params' => false
          }
        end

        def do_logout(cookies)
          send_request({ 'uri' => normalize_uri('/dana-na/auth/logout.cgi?delivery=psal'), 'cookie' => cookies })
        end

        def do_login(username, password)
          protocol = ssl ? 'https' : 'http'
          peer = "#{host}:#{port}"
          user_req = create_user_request(username, password, protocol, peer)
          begin
            res = send_request(user_req)
          rescue ::Rex::ConnectionError, ::Rex::ConnectionProxyError, ::Errno::ECONNRESET, ::Errno::EINTR, ::Rex::TimeoutError, ::Timeout::Error, ::EOFError => e
            return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e }
          end
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unable to connect to the Ivanti service' } if res.nil?
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: "Received an unexpected status code: #{res.code}" } if res.code != 302
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unexpected response' } if !res.headers&.key?('location')

          if res.headers['location'] == '/dana-na/auth/url_default/welcome.cgi?p=ip%2Dblocked'
            sleep(2 * 60) # 2 minutes
            res = send_request(user_req)
          end

          return { status: ::Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.to_s } if res.headers['location'] == '/dana-na/auth/url_default/welcome.cgi?p=user%2Dconfirm'

          if res.headers['location'] == '/dana/home/starter0.cgi?check=yes'
            do_logout(res.get_cookies)
            return { status: ::Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.to_s }
          else
            return { status: ::Metasploit::Model::Login::Status::INCORRECT, proof: res.to_s }
          end
        end

        # Attempts to login to the server.
        #
        # @param [Metasploit::Framework::Credential] credential The credential information.
        # @return [Result] A Result object indicating success or failure
        def attempt_login(credential)
          # focus on creating Result object, pass it to #login routine and return Result object
          result_options = {
            credential: credential,
            host: @host,
            port: @port,
            protocol: 'tcp',
            service_name: 'ivanti'
          }

          if @admin
            login_result = do_admin_login(credential.public, credential.private)
          else
            login_result = do_login(credential.public, credential.private)
          end

          result_options.merge!(login_result)
          Result.new(result_options)
        end

      end
    end
  end
end
