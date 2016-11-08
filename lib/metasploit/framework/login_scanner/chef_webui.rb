
require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # The ChefWebUI HTTP LoginScanner class provides methods to authenticate to Chef WebUI
      class ChefWebUI < HTTP

        DEFAULT_PORT  = 80
        PRIVATE_TYPES = [ :password ]

        # @!attribute session_name
        #   @return [String] Cookie name for session_id
        attr_accessor :session_name

        # @!attribute session_id
        #   @return [String] Cookie value
        attr_accessor :session_id

        # Decides which login routine and returns the results
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Result]
        def attempt_login(credential)
          result_opts = {
            credential: credential,
            status: Metasploit::Model::Login::Status::INCORRECT,
            proof: nil,
            host: host,
            port: port,
            protocol: 'tcp'
          }

          begin
            status = try_login(credential)
            result_opts.merge!(status)
          rescue ::EOFError, Errno::ECONNRESET, Rex::ConnectionError, OpenSSL::SSL::SSLError, ::Timeout::Error => e
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
          end

          Result.new(result_opts)
        end

        # (see Base#check_setup)
        def check_setup
          begin
            res = send_request({'uri' => normalize_uri('/users/login')})
            return "Connection failed" if res.nil?

            if res.code != 200
              return "Unexpected HTTP response code #{res.code} (is this really Chef WebUI?)"
            end

            if res.body.to_s !~ /<title>Chef Server<\/title>/
              return "Unexpected HTTP body (is this really Chef WebUI?)"
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
          cli = Rex::Proto::Http::Client.new(host, port, {'Msf' => framework, 'MsfExploit' => self}, ssl, ssl_version, proxies, http_username, http_password)
          configure_http_client(cli)
          cli.connect
          req = cli.request_raw(opts)
          res = cli.send_recv(req)

          # Save the session ID cookie
          if res && res.get_cookies =~ /(_\w+_session)=([^;$]+)/i
            self.session_name = $1
            self.session_id = $2
          end

          res
        end

        # Sends a login request
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Rex::Proto::Http::Response] The HTTP auth response
        def try_credential(csrf_token, credential)

          data  = "utf8=%E2%9C%93" # ✓
          data << "&authenticity_token=#{Rex::Text.uri_encode(csrf_token)}"
          data << "&name=#{Rex::Text.uri_encode(credential.public)}"
          data << "&password=#{Rex::Text.uri_encode(credential.private)}"
          data << "&commit=login"

          opts = {
            'uri'     => normalize_uri('/users/login_exec'),
            'method'  => 'POST',
            'data'    => data,
            'headers' => {
              'Content-Type'   => 'application/x-www-form-urlencoded',
              'Cookie'         => "#{self.session_name}=#{self.session_id}"
            }
          }

          send_request(opts)
        end


        # Tries to login to Chef WebUI
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Hash]
        #   * :status [Metasploit::Model::Login::Status]
        #   * :proof [String] the HTTP response body
        def try_login(credential)

          # Obtain a CSRF token first
          res = send_request({'uri' => normalize_uri('/users/login')})
          unless (res && res.code == 200 && res.body =~ /input name="authenticity_token" type="hidden" value="([^"]+)"/m)
            return {:status => Metasploit::Model::Login::Status::UNTRIED, :proof => res.body}
          end

          csrf_token = $1

          res = try_credential(csrf_token, credential)
          if res && res.code == 302
            opts = {
              'uri'     => normalize_uri("/users/#{credential.public}/edit"),
              'method'  => 'GET',
              'headers' => {
                'Cookie'  => "#{self.session_name}=#{self.session_id}"
              }
            }
            res = send_request(opts)
            if (res && res.code == 200 && res.body.to_s =~ /New password for the User/)
              return {:status => Metasploit::Model::Login::Status::SUCCESSFUL, :proof => res.body}
            end
          end

          {:status => Metasploit::Model::Login::Status::INCORRECT, :proof => res.body}
        end

      end
    end
  end
end

