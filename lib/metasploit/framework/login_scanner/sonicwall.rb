require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      # SonicWall Login Scanner supporting
      # - User Login
      # - Admin Login
      class SonicWall < HTTP

        DEFAULT_SSL_PORT = [443, 4433]
        LIKELY_PORTS = [443, 4433]
        LIKELY_SERVICE_NAMES = [
          'SonicWall Network Security'
        ]
        PRIVATE_TYPES = [:password]
        REALM_KEY = nil

        attr_accessor :domain

        def req_params_base
          {
            'method' => 'POST',
            'uri' => normalize_uri('/api/sonicos/auth'),
            'ctype' => 'application/json',
            # Force SSL as the application uses non-standard TCP port for HTTPS - 4433
            'ssl' => true
          }
        end

        def auth_details_req
          params = req_params_base

          #
          # Admin and SSLVPN user login procedure differs only in usage of domain field in JSON data
          #
          params.merge!({
            'data' => JSON.pretty_generate(@domain.blank? ? {
              'override' => false,
              'snwl' => true
            } : { 'domain' => @domain, 'override' => false, 'snwl' => true })
          })
          return params
        end

        def auth_req(header)
          params = req_params_base

          params.merge!({
            'headers' =>
            {
              'Authorization' => header.join(', ')
            }
          })

          params.merge!({
            'data' => JSON.pretty_generate(@domain.empty? ? {
              'override' => false,
              'snwl' => true
            } : { 'domain' => @domain, 'override' => false, 'snwl' => true })
          })

          return params
        end

        def get_auth_details(username, password)
          send_request(auth_details_req)
        end

        def try_login(header)
          send_request(auth_req(header))
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
          if res&.code == 200 && res.body&.include?('SonicWall')
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
          begin
            res = get_auth_details(username, password)
          rescue ::Rex::ConnectionError, ::Rex::ConnectionProxyError, ::Errno::ECONNRESET, ::Errno::EINTR, ::Rex::TimeoutError, ::Timeout::Error, ::EOFError => e
            return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e }
          end

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Invalid response' } unless res
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Failed to receive a authentication details' } unless res&.headers && res.headers.key?('X-SNWL-Authenticate')

          res.headers['X-SNWL-Authenticate'] =~ /Digest (.*)/

          parameters = {}
          ::Regexp.last_match(1).split(/,[[:space:]]*/).each do |p|
            k, v = p.split('=', 2)
            parameters[k] = v.gsub('"', '')
          end
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Incorrect authentication header' } if parameters.empty?

          digest_auth = Rex::Proto::Http::AuthDigest.new
          auth_header = digest_auth.digest(username, password, 'POST', '/api/sonicos/auth', parameters)
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Could not calculate hash' } unless auth_header

          #-- send the actual request with all hashes and information

          res = try_login(auth_header)

          return { status: ::Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.to_s } if res&.code == 200


          msg_json = res.get_json_document

          return { status: ::Metasploit::Model::Login::Status::INCORRECT, proof: res.to_s } unless msg_json
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
