require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      class SonicWall < HTTP

        def auth_details_req
          {
            'method' => 'POST',
            'uri' => normalize_uri('/api/sonicos/auth'),
            'ctype' => 'application/json',
            'data' => JSON.pretty_generate({
              'override' => false,
              'snwl' => true
            })
          }
        end

        # Rewrite crypto stuff into separate class
        def get_response_hash(algorithm, realm, qop, nonce, opaque, username, password)
          if algorithm == 'MD5_sess'
            hash_obj = Digest::MD5.new
            ha1 = hash_obj.hexdigest("#{hash_obj.hexdigest("#{username}:#{realm}:#{password}")}:#{nonce}:cnonce")
          else
            case algorithm
            when '' || 'MD5'
              hash_obj = Digest::MD5.new
            when 'SHA-256'
              hash_obj = Digest::SHA256.new
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
            cnonce = '7VSaRKfBSRotzMPXkYXOog=='
            return hash_obj.hexdigest("#{ha1}:#{nonce}:00000001:#{cnonce}:#{qop}:#{ha2}")
          else
            return hash_obj.hexdigest("#{ha1}:#{nonce}:#{ha2}")
          end
        end

        def get_auth_details(username, password)
          res = send_request(auth_details_req)

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Invalid response' } unless res
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Failed to receive a authentication details' } unless res&.headers && res.headers.key?('X-SNWL-Authenticate')

          snwl_authenticate_header = res.headers['X-SNWL-Authenticate']

          algorithm = snwl_authenticate_header&.match(/^Digest algorithm=([a-zA-Z0-9-]+),/)

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Malformed authentication data' } unless algorithm

          realm = snwl_authenticate_header&.match(/realm="([^\s]*)",/)

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Malformed authentication data' } unless realm

          snwl_authenticate_header&.match(/qop="([a-zA-Z]*)",/)

          nonce = snwl_authenticate_header&.match(/nonce="([^\s]*)",/)

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Malformed authentication data' } unless nonce

          opaque = snwl_authenticate_header&.match(/opaque="([^\s]*)",/)

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Malformed authentication data' } unless opaque

          res_hash = get_response_hash(algorithm, realm, qop, nonce, opaque, username, password)

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Could not calculate hash' } unless res_hash

        end

        def do_login(username, password)
          get_auth_details(username, password)
        end

        def attempt_login(credential)
          result_options = {
            credential: credential,
            host: @host,
            port: @port,
            protocol: 'tcp',
            service_name: 'sonicwall'
          }
          result_options.merge!(do_login(credential.public, credential.private))
          Result.new(result_options)
        end
      end
    end
  end
end
