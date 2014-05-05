require 'rex/proto/http'
require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'

module Metasploit
  module Framework
    module LoginScanner
      #
      # HTTP-specific login scananer.
      #
      class HTTP
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket


        # @!attribute uri
        #   @return [String] The path and query string on the server to
        #     authenticate to.
        attr_accessor :uri

        validates :uri, presence: true, length: { minimum: 1 }

        # Attempt a single login with a single credential against the target.
        #
        # @param credential [Credential] The credential object to attempt to
        #   login with.
        # @return [Result] A Result object indicating success or failure
        def attempt_login(credential)
          ssl = false if ssl.nil?

          result_opts = {
            private: credential.private,
            public: credential.public,
            realm: nil,
            status: :failed,
            proof: nil
          }

          http_client = Rex::Proto::Http::Client.new(
            host, port, {}, ssl, ssl_version,
            nil, credential.public, credential.private
          )

          http_client.connect
          begin
            request = http_client.request_cgi('uri' => uri)

            # First try to connect without logging in to make sure this
            # resource requires authentication. We use #_send_recv for
            # that instead of #send_recv.
            response = http_client._send_recv(request)
            if response && response.code == 401 && response.headers['WWW-Authenticate']
              # Now send the creds
              response = http_client.send_auth(
                response, request.opts, connection_timeout, true
              )
              if response && response.code == 200
                result_opts.merge!(status: :success, proof: response.headers)
              end
            else
              result_opts.merge!(status: :error)
            end
          rescue ::EOFError, Rex::ConnectionError, ::Timeout::Error
            result_opts.merge!(status: :connection_error)
          ensure
            http_client.close
          end

          Result.new(result_opts)
        end

        private

        # This method sets the sane defaults for things
        # like timeouts and TCP evasion options
        def set_sane_defaults
          self.max_send_size = 0 if self.max_send_size.nil?
          self.send_delay = 0 if self.send_delay.nil?
        end

      end
    end
  end
end
