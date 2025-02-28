require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      # SonicWall Login Scanner supporting
      # - User Login
      # - Admin Login
      class SonicWall < HTTP

        # Basic implementation of HTTP Digest Auth, supporting MD5 and SHA256
        module HTTPDigestAuth
          def calculate_response(algorithm, realm, qop, nonce, opaque, username, password)
            #
            # Making reference to desired hash function. Since hashing function has to be called multiple times within function, it seemed like it makes more sense to have it stored locally rather than call Digest::[HASH FUNCTION].hexdigest every time.
            #
            if algorithm == 'MD5_sess'
              hash_obj = Digest::MD5
              ha1 = hash_obj.hexdigest("#{hash_obj.hexdigest("#{username}:#{realm}:#{password}")}:#{nonce}:cnonce")
            else
              case algorithm
              when '' || 'MD5'
                hash_obj = Digest::MD5
              when 'SHA-256'
                hash_obj = Digest::SHA256
              else
                return nil
              end
              ha1 = hash_obj.hexdigest("#{username}:#{realm}:#{password}")
            end

            if qop == 'auth' || qop == ''
              ha2 = hash_obj.hexdigest('POST:/api/sonicos/auth')
            elsif qop == 'auth-int'
              ha2 = hash_obj.hexdigest('POST:/api/sonicos/auth:23')
            else
              return nil
            end
            if qop == 'auth' || qop == 'auth-int'
              #
              # client nonce (cnonce) is generated for every run, originally, it should be 32 bytes encoded in Base64, but this seems to be working as well
              # nc - constant
              #
              cnonce = Rex::Text.rand_text_base64(24)
              nc = '00000001'
              return hash_obj.hexdigest("#{ha1}:#{nonce}:#{nc}:#{cnonce}:#{qop}:#{ha2}"), cnonce, nc
            else
              return hash_obj.hexdigest("#{ha1}:#{nonce}:#{ha2}"), nil, nil
            end
          end
        end

        include HTTPDigestAuth
        DEFAULT_SSL_PORT = [443, 4433]
        LIKELY_PORTS = [443, 4433]
        LIKELY_SERVICE_NAMES = [
          'SonicWall Network Security'
        ]
        PRIVATE_TYPES = [:password]
        REALM_KEY = nil

        def initialize(scanner_config, domain)
          @domain = domain
          super(scanner_config)
        end

        def auth_details_req
          {
            'method' => 'POST',
            'uri' => normalize_uri('/api/sonicos/auth'),
            'ctype' => 'application/json',
            # Force SSL as the application uses non-standard TCP port for HTTPS - 4433
            'ssl' => true
          }
        end

        def auth_req(username, realm, algorithm, nonce, nc, cnonce, qop, opaque, response)
          {
            'method' => 'POST',
            'uri' => normalize_uri('/api/sonicos/auth'),
            'ctype' => 'application/json',
            # Force SSL as the application uses non-standard TCP port for HTTPS - 4433
            'ssl' => true,
            'headers' => {
              'Authorization' => %(Digest username="#{username}", realm="#{realm}", uri="/api/sonicos/auth", algorithm=#{algorithm}, nonce=#{nonce}, nc=#{nc}, cnonce="#{cnonce}", qop=#{qop}, opaque="#{opaque}", response="#{response}")
            }
          }
        end

        def get_auth_details(username, password)
          request_param = auth_details_req
          #
          # Admin and SSLVPN user login procedure differs only in usage of domain field in JSON data
          #
          if @domain == ''
            request_param['data'] = JSON.pretty_generate({
              'override' => false,
              'snwl' => true
            })

          else
            request_param['data'] = JSON.pretty_generate({
              'domain' => @domain,
              'override' => false,
              'snwl' => true
            })
          end
          send_request(request_param)
        end

        def try_login(username, realm, algorithm, nonce, nc, cnonce, qop, opaque, resp_hash)
          request_param = auth_req(username, realm, algorithm, nonce, nc, cnonce, qop, opaque, resp_hash)
          #
          # Admin and SSLVPN user login procedure differs only in usage of domain field in JSON data
          #
          if @domain == ''
            request_param['data'] = JSON.pretty_generate({
              'override' => false,
              'snwl' => true
            })

          else
            request_param['data'] = JSON.pretty_generate({
              'domain' => @domain,
              'override' => false,
              'snwl' => true
            })
          end
          send_request(request_param)
        end

        def get_resp_msg(msg)
          msg.dig('status', 'info', 0, 'message')
        end

        def check_setup
          request_params = {
            'method' => 'GET',
            'uri' => normalize_uri('/sonicui/7/login/')
          }
          res = send_request(request_params)
          if res && res.code == 200 && res.body&.include?('SonicWall')
            return false
          end

          'Unable to locate "SonicWall" in body. (Is this really SonicWall?)'
        end

        #
        # The login procedure is two-step procedure for SonicWall due to HTTP Digest Authentication. In the first request, client receives data,cryptographic hashes and algorithm selection from server. It should calculate final response hash from username, password and additional data received from server. The second request contains all this information.
        #
        def do_login(username, password, depth)
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Waiting too long in lockout' } if depth >= 2

          #-- get authentication details from first request
          res = get_auth_details(username, password)

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Invalid response' } unless res
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Failed to receive a authentication details' } unless res&.headers && res.headers.key?('X-SNWL-Authenticate')

          snwl_authenticate_header = res.headers['X-SNWL-Authenticate']

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Incorrect authentication header' } unless snwl_authenticate_header

          algorithm = snwl_authenticate_header[/^Digest algorithm=([a-zA-Z0-9-]+),/, 1]
          realm = snwl_authenticate_header[/realm="([^\s]*)",/, 1]
          qop = snwl_authenticate_header[/qop="([a-zA-Z]*)",/, 1]
          nonce = snwl_authenticate_header[/nonce="([^\s]*)",/, 1]
          opaque = snwl_authenticate_header[/opaque="([\w\W]+)"/, 1]

          resp_hash, cnonce, nc = calculate_response(algorithm, realm, qop, nonce, opaque, username, password)

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Could not calculate hash' } unless resp_hash

          #-- send the actual request with all hashes and information

          res = try_login(username, realm, algorithm, nonce, nc, cnonce, qop, opaque, resp_hash)

          return { status: ::Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.to_s } if res&.code == 200

          msg_json = res.get_json_document

          return { status: ::Metasploit::Model::Login::Status::INCORRECT, proof: res.to_s } unless msg_json && msg_json.is_a?(Hash)

          msg = get_resp_msg(msg_json)

          if msg == 'User is locked out'
            sleep(5 * 60)
            return do_login(username, password, depth + 1)
          end

          return { status: ::Metasploit::Model::Login::Status::INCORRECT, proof: msg }
        end

        def attempt_login(credential)
          result_options = {
            credential: credential,
            host: @host,
            port: @port,
            protocol: 'tcp',
            service_name: 'sonicwall'
          }
          result_options.merge!(do_login(credential.public, credential.private, 1))
          Result.new(result_options)
        end
      end
    end
  end
end
