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
        
        def auth_req(username,realm,algorithm,nonce,nc,cnonce,qop,opaque,response)
          {
            'method' => 'POST',
            'uri' => normalize_uri('/api/sonicos/auth'),
            'ctype' => 'application/json',
            'headers' => {
              'Authorization' => "Digest username=\"#{username}\", realm=\"#{realm}\", uri=\"/api/sonicos/auth\", algorithm=#{algorithm}, nonce=#{nonce}, nc=#{nc}, cnonce=\"#{cnonce}\", qop=#{qop}, opaque=\"#{opaque}\", response=\"#{response}\""
            },
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
            ha1 = Digest::SHA256.hexdigest("#{username}:#{realm}:#{password}")
          end

          if qop == 'auth' || qop == ''
            ha2 = Digest::SHA256.hexdigest('POST:/api/sonicos/auth')
          elsif qop == 'auth-int'
            ha2 = Digest::SHA256.hexdigest('POST:/api/sonicos/auth:23')
          else
            return nil
          end

          if qop == 'auth' || qop == 'auth-int'
            cnonce = '7VSaRKfBSRotzMPXkYXOog=='
            return Digest::SHA256.hexdigest("#{ha1}:#{nonce}:00000001:#{cnonce}:#{qop}:#{ha2}")
          else
            return Digest::SHA256.hexdigest("#{ha1}:#{nonce}:#{ha2}")
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

          qop = snwl_authenticate_header&.match(/qop="([a-zA-Z]*)",/)

          nonce = snwl_authenticate_header&.match(/nonce="([^\s]*)",/)

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Malformed authentication data' } unless nonce

          opaque = snwl_authenticate_header&.match(/opaque="([\w\W]+)"/)

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Malformed authentication data' } unless opaque
        
          algorithm = algorithm[1]
          realm = realm[1]
          qop = qop ? qop[1] : nil
          nonce = nonce[1]
          opaque = opaque[1]

          nonce_dec = Base64.strict_decode64(nonce)
          puts nonce_dec 
          puts nonce_dec.map { |b| sprintf(", 0x%02X",b) }.join



          resp_hash = get_response_hash(algorithm, realm, qop, nonce, opaque, username, password)
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Could not calculate hash' } unless resp_hash
          nc='00000001'
          cnonce = 'fFmqlT4WSjGHgCECh1OUrg=='
          res = send_request(auth_req(username,realm,algorithm,nonce,nc,cnonce,qop,opaque,resp_hash))
        
          puts res
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
