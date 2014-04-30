require 'rex/proto/http'

module Metasploit
  module Framework
    module LoginScanner
      #
      # HTTP-specific login scananer.
      #
      class HTTP
        include ActiveModel::Validations

        # @!attribute connection_timeout
        #   @return [Numeric] The timeout in seconds for a single connection
        attr_accessor :connection_timeout

        # @!attribute cred_details
        #   @return [Array] An array of Credential objects
        attr_accessor :cred_details

        # @!attribute failures
        #   @return [Array] Array of of result objects that failed
        attr_accessor :failures

        # @!attribute host
        #   @return [String] The IP address or hostname to connect to
        attr_accessor :host

        # @!attribute port
        #   @return [Fixnum] The port to connect to
        attr_accessor :port

        # @!attribute ssl
        #   @return [Boolean] Whether this client makes SSL connections
        attr_accessor :ssl

        # @!attribute ssl_version
        #   @return [Symbol] The version of SSL/TLS to use when connecting
        attr_accessor :ssl_version

        # @!attribute stop_on_success
        #   @return [Boolean] Whether the scanner should stop when it has found one working Credential
        attr_accessor :stop_on_success

        # @!attribute successes
        #   @return [Array] Array of of result objects that succeded
        attr_accessor :successes

        # @!attribute uri
        #   @return [String] The path and query string on the server to
        #     authenticate to.
        attr_accessor :uri

        validates :connection_timeout, presence: true

        validates :cred_details, presence: true

        validates :host, presence: true

        validates :port,
                  presence: true,
                  numericality: {
                      only_integer:             true,
                      greater_than_or_equal_to: 1,
                      less_than_or_equal_to:    0xffff
                  }

        validates :uri, presence: true, length: { minimum: 1 }

        # @param attributes [Hash{Symbol => String,nil}]
        def initialize(attributes = {})
          attributes.each do |attribute, value|
            public_send("#{attribute}=", value)
          end
          self.successes = []
          self.failures = []
        end

        # Attempt a single login with a single credential against the target.
        #
        # @param credential [Credential] The credential object to
        #   attempt to login with.
        # @return [Result] The Result object indicating success or
        #   failure
        def attempt_login(credential)
          ssl = false if ssl.nil?

          result_opts = {
            private: credential.private,
            public: credential.public,
            realm: nil
          }

          http_client = Rex::Proto::Http::Client.new(
            host, port, {}, ssl, ssl_version,
            nil, credential.public, credential.private
          )

          http_client.connect
          begin
            request = http_client.request_cgi('uri' => uri)
            p request

            # First try to connect without logging in to make sure this
            # resource requires authentication. We use #_send_recv for
            # that instead of #send_recv.
            response = http_client._send_recv(request)
            if response && response.code == 401 && response.headers['WWW-Authenticate']
              # Now send the creds
              response = http_client.send_auth(response, request.opts, connection_timeout, true)
              if response && response.code == 200
                result_opts.merge!(status: :success, proof: response.headers)
              else
                result_opts.merge!(status: :failed, proof: nil)
              end
            else
              result_opts.merge!(status: :failed, proof: nil)
            end

            p response.code, response.headers
          ensure
            http_client.close
          end


          Result.new(result_opts)
        end

        # Run all the login attempts against the target.
        #
        # This method calls {attempt_login} once for each credential.
        # Results are stored in {successes} and {failures}. If a block
        # is given, each result will be yielded as we go.
        #
        # @yield [result]
        # @yieldparam result [Result] The LoginScanner Result object for
        #   the attempt
        # @yieldreturn [void]
        # @return [void]
        def scan!
          valid!
          cred_details.each do |credential|
            result = attempt_login(credential)
            result.freeze

            yield result if block_given?

            if result.success?
              successes << result
              break if stop_on_success
            else
              failures << result
            end
          end
        end

        # @raise [Metasploit::Framework::LoginScanner::Invalid] if the attributes are not valid on the scanner
        def valid!
          unless valid?
            raise Metasploit::Framework::LoginScanner::Invalid.new(self)
          end
        end

        private


      end
    end
  end
end
