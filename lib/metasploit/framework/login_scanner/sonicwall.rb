require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      class SonicWall < HTTP
        def auth_details_req
          ssl ? 'https' : 'http'
          {
            'method' => 'POST',
            'uri' => normalize_uri('/api/sonicos/auth'),
            'ctype' => 'application/json',
            'data' => JSON.pretty_generate({
              'domain' => @domain,
              'override' => false,
              'snwl' => true
            }),
            'ssl' => true
          }
        end

        def admin_auth_details_req
          ssl ? 'https' : 'http'
          {
            'method' => 'POST',
            'uri' => normalize_uri('/api/sonicos/auth'),
            'ctype' => 'application/json',
            'data' => JSON.pretty_generate({
              'override' => false,
              'snwl' => true
            }),
            'ssl' => true
          }
        end

        def auth_req(username, realm, algorithm, nonce, nc, cnonce, qop, opaque, response)
          ssl ? 'https' : 'http'
          {
            'method' => 'POST',
            'uri' => normalize_uri('/api/sonicos/auth'),
            'ctype' => 'application/json',
            'ssl' => true,
            'headers' => {
              'Authorization' => "Digest username=\"#{username}\", realm=\"#{realm}\", uri=\"/api/sonicos/auth\", algorithm=#{algorithm}, nonce=#{nonce}, nc=#{nc}, cnonce=\"#{cnonce}\", qop=#{qop}, opaque=\"#{opaque}\", response=\"#{response}\""
            },
            'data' => JSON.pretty_generate({
              'domain' => @domain,
              'override' => false,
              'snwl' => true
            })
          }
        end

        def admin_auth_req(username, realm, algorithm, nonce, nc, cnonce, qop, opaque, response)
          protocol = ssl ? 'https' : 'http'
          peer = "#{host}:#{port}"
          {
            'method' => 'POST',
            'uri' => normalize_uri('/api/sonicos/auth'),
            'ctype' => 'application/json',
            'ssl' => true,
            'headers' => {
              'Authorization' => "Digest username=\"#{username}\", realm=\"#{realm}\", uri=\"/api/sonicos/auth\", algorithm=#{algorithm}, nonce=#{nonce}, nc=#{nc}, cnonce=\"#{cnonce}\", qop=#{qop}, opaque=\"#{opaque}\", response=\"#{response}\"",
              'Referer' => "#{protocol}://#{peer}/api/sonicos/auth"
            },
            'data' => JSON.pretty_generate({
              'override' => false,
              'snwl' => true
            })
          }
        end

        # Rewrite crypto stuff into separate class
        def get_response_hash(algorithm, realm, qop, cnonce, nc, nonce, opaque, username, password)
          if algorithm == 'MD5_sess'
            hash_obj = Digest::MD5.new
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
            return hash_obj.hexdigest("#{ha1}:#{nonce}:#{nc}:#{cnonce}:#{qop}:#{ha2}")
          else
            return hash_obj.hexdigest("#{ha1}:#{nonce}:#{ha2}")
          end
        end

        def get_auth_details(username, password)
          res = send_request(@domain == '' ? admin_auth_details_req : auth_details_req)

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
          nc = '00000001'
          cnonce = Rex::Text.rand_text_base64(24)

          resp_hash = get_response_hash(algorithm, realm, qop, cnonce, nc, nonce, opaque, username, password)
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Could not calculate hash' } unless resp_hash

          res = send_request(@domain == '' ? admin_auth_req(username, realm, algorithm, nonce, nc, cnonce, qop, opaque, resp_hash) : auth_req(username, realm, algorithm, nonce, nc, cnonce, qop, opaque, resp_hash))

          return { status: ::Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.to_s } if res&.code == 200

          return { status: ::Metasploit::Model::Login::Status::INCORRECT, proof: res.to_s }
        end

        def initialize(scanner_config, domain)
          @domain = domain
          super(scanner_config)
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
