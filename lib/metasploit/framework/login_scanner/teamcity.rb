require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with JetBrains TeamCity instances.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class TeamCity < HTTP

        module Crypto
          # https://github.com/openssl/openssl/blob/a08a145d4a7e663dd1e973f06a56e983a5e916f7/crypto/rsa/rsa_pk1.c#L125
          # https://datatracker.ietf.org/doc/html/rfc3447#section-7.2.1
          def pkcs1pad2(text, n)
            raise ArgumentError, "Cannot pad the text: '#{text.inspect}'" unless text.is_a?(String)
            raise ArgumentError, "Invalid message length: '#{n.inspect}'" unless n.is_a?(Integer)

            bytes_per_char = two_byte_chars?(text) ? 2 : 1
            if n < ((bytes_per_char * text.length) + 11)
              raise ArgumentError, 'Message too long'
            end

            ba = Array.new(n, 0)
            n -= 1
            ba[n] = text.length

            i = text.length - 1

            while i >= 0 && n > 0
              char_code = text[i].ord
              i -= 1

              num_bytes = bytes_per_char

              while num_bytes > 0
                next_byte = char_code % 0x100
                char_code >>= 8

                n -= 1
                ba[n] = next_byte

                num_bytes -= 1
              end
            end
            n -= 1
            ba[n] = 0

            while n > 2
              n -= 1
              ba[n] = rand(1..255) # Can't be a null byte.
            end

            n -= 1
            ba[n] = 2
            n -= 1
            ba[n] = 0

            ba.pack("C*").unpack1("H*").to_i(16)
          end

          # @param [String] modulus
          # @param [String] exponent
          # @param [String] text
          # @return [String]
          def rsa_encrypt(modulus, exponent, text)
            n = modulus.to_i(16)
            e = exponent.to_i(16)

            padded_as_big_int = pkcs1pad2(text, (n.bit_length + 7) >> 3)
            encrypted = padded_as_big_int.to_bn.mod_exp(e, n)
            h = encrypted.to_s(16)

            h.length.odd? ? h.prepend('0') : h
          end

          def two_byte_chars?(str)
            raise ArgumentError, 'Unable to check char size for non-string value' unless str.is_a?(String)

            str.each_codepoint do |codepoint|
              return true if codepoint >> 8 > 0
            end

            false
          end

          def max_data_size(str)
            raise ArgumentError, 'Unable to get maximum data size for non-string value' unless str.is_a?(String)

            # Taken from TeamCity's login page JavaScript sources.
            two_byte_chars?(str) ? 58 : 116
          end

          # @param [String] text The text to encrypt.
          # @param [String] public_key The hex representation of the public key to use.
          # @return [String] A string blob.
          def encrypt_data(text, public_key)
            raise ArgumentError, "Cannot encrypt the provided data: '#{text.inspect}'" unless text.is_a?(String)
            raise ArgumentError, "Cannot encrypt data with the public key: '#{public_key.inspect}'" unless public_key.is_a?(String)

            exponent = '10001'
            e = []
            utf_text = text.dup.force_encoding(::Encoding::UTF_8)
            g = max_data_size(utf_text)

            c = 0
            while c < utf_text.length
              b = [utf_text.length, c + g].min

              a = utf_text[c..b]

              encrypt = rsa_encrypt(public_key, exponent, a)
              e.push(encrypt)
              c += g
            end

            e.join('')
          end
        end

        include Crypto

        DEFAULT_PORT         = 8111
        LIKELY_PORTS         = [8111]
        LIKELY_SERVICE_NAMES = [
          # Comes from nmap 7.95 on MacOS
          'skynetflow',
          'teamcity',
          'http',
          'https'
        ]
        PRIVATE_TYPES        = [:password]
        REALM_KEY            = nil

        LOGIN_PAGE = 'login.html'
        LOGOUT_PAGE = 'ajax.html?logout=1'
        SUBMIT_PAGE = 'loginSubmit.html'

        class TeamCityError < StandardError; end
        class StackLevelTooDeepError < TeamCityError; end
        class NoPublicKeyError < TeamCityError; end
        class PublicKeyExpiredError < TeamCityError; end
        class DecryptionError < TeamCityError; end
        class ServerNeedsSetupError < TeamCityError; end

        # Checks if the target is JetBrains TeamCity. The login module should call this.
        #
        # @return [Boolean] TrueClass if target is TeamCity, otherwise FalseClass
        def check_setup
          request_params = {
            'method' => 'GET',
            'uri' => normalize_uri(@uri.to_s, LOGIN_PAGE)
          }
          res = send_request(request_params)

          if res && res.code == 200 && res.body&.include?('Log in to TeamCity')
            return false
          end

          "Unable to locate \"Log in to TeamCity\" in body. (Is this really TeamCity?)"
        end

        # Extract the server's public key from the server.
        # @return [Hash] A hash with a status and an error or the server's public key.
        def get_public_key
          request_params = {
            'method' => 'GET',
            'uri' => normalize_uri(@uri.to_s, LOGIN_PAGE)
          }

          begin
            res = send_request(request_params)
          rescue ::Rex::ConnectionError, ::Rex::ConnectionProxyError, ::Errno::ECONNRESET, ::Errno::EINTR, ::Rex::TimeoutError, ::Timeout::Error, ::EOFError => e
            return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e }
          end

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unable to connect to the TeamCity service' } if res.nil?

          raise ServerNeedsSetupError, 'The server has not performed the initial setup' if res.code == 503

          html_doc = res.get_html_document
          public_key = html_doc.xpath('//input[@id="publicKey"]/@value').text
          raise NoPublicKeyError, 'Could not find the TeamCity public key in the HTML document' if public_key.empty?

          { status: :success, proof: public_key }
        end

        # Create a login request for the provided credentials.
        # @param [String] username The username to create the login request for.
        # @param [String] password The password to log in with.
        # @param [String] public_key The public key to encrypt the password with.
        # @return [Hash] The login request parameter hash.
        def create_login_request(username, password, public_key)
          {
            'method' => 'POST',
            'uri' => normalize_uri(@uri.to_s, SUBMIT_PAGE),
            'ctype' => 'application/x-www-form-urlencoded',
            'vars_post' => {
              username: username,
              remember: true,
              _remember: '',
              submitLogin: 'Log in',
              publicKey: public_key,
              encryptedPassword: encrypt_data(password, public_key)
            }
          }
        end

        # Try logging in with the provided username, password and public key.
        # @param [String] username The username to send the login request for.
        # @param [String] password The user's password.
        # @param [String] public_key The public key used to encrypt the password.
        # @return [Hash] A hash with the status and an error or the response.
        def try_login(username, password, public_key, retry_counter = 0)
          raise StackLevelTooDeepError, 'try_login stack level too deep!' if retry_counter >= 2

          login_request = create_login_request(username, password, public_key)

          begin
            res = send_request(login_request)
          rescue ::Rex::ConnectionError, ::Rex::ConnectionProxyError, ::Errno::ECONNRESET, ::Errno::EINTR, ::Rex::TimeoutError, ::Timeout::Error, ::EOFError => e
            return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e }
          end

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unable to connect to the TeamCity service' } if res.nil?
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: "Received an unexpected status code: #{res.code}" } if res.code != 200

          # Check if the current username is timed out. Sleep if so.
          # TODO: This can be improved. The `try_login` method should not block until it can retry credentials.
          # This responsibility should fall onto the caller, and the caller should keep track of the tried, locked out and untried sets of credentials,
          # and it should be up to the caller and its scheduler algorithm to retry credentials, rather than force this method to block.
          # Currently, those building blocks are not available, so this is the approach I have implemented.
          timeout = res.body.match(/login only in (?<timeout>\d+)s/)&.named_captures&.dig('timeout')&.to_i
          if timeout
            framework_module.print_status "#{@host}:#{@port} - User '#{username}:#{password}' locked out for #{timeout} seconds. Sleeping, and retrying..." if framework_module
            sleep(timeout + 1)
            return try_login(username, password, public_key, retry_counter + 1)
          end

          return { status: ::Metasploit::Model::Login::Status::INCORRECT, proof: res } if res.body.match?('Incorrect username or password')

          raise DecryptionError, 'The server failed to decrypt the encrypted password' if res.body.match?('DecryptionFailedException')
          raise PublicKeyExpiredError, 'The server public key has expired' if res.body.match?('publicKeyExpired')

          # After filtering out known failures, default to retuning the credential as working.
          # This way, people are more likely to notice any incorrect credential reporting going forward and report them,
          # the scenarios for which can then be correctly implemented and handled similar to the above.
          { status: :success, proof: res }
        end

        # Send a logout request for the provided user's headers.
        # This header stores the user's cookie.
        def logout_with_headers(headers)
          logout_params = {
            'method' => 'POST',
            'uri' => normalize_uri(@uri.to_s, LOGOUT_PAGE),
            'headers' => headers
          }

          begin
            send_request(logout_params)
          rescue Rex::ConnectionError => _e
            # ignore
          end
        end

        def attempt_login(credential)
          result_options = {
            credential:   credential,
            host:         @host,
            port:         @port,
            protocol:     'tcp',
            service_name: 'teamcity'
          }

          if @public_key.nil?
            public_key_result = get_public_key
            return Result.new(result_options.merge(public_key_result)) if public_key_result[:status] != :success

            @public_key = public_key_result[:proof]
          end

          login_result = try_login(credential.public, credential.private, @public_key)
          return Result.new(result_options.merge(login_result)) if login_result[:status] != :success

          # Ensure we log the user out, so that our logged in session does not appear under the user's profile.
          logout_with_headers(login_result[:proof].headers)

          result_options[:status] = ::Metasploit::Model::Login::Status::SUCCESSFUL
          Result.new(result_options)
        end

        private

        attr_accessor :public_key

      end
    end
  end
end
