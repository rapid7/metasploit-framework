require 'metasploit/framework/login_scanner/http'
require 'digest'

module Metasploit
  module Framework
    module LoginScanner

      class BavisionCamerasException < StandardError; end

      class BavisionCameras < HTTP

        DEFAULT_PORT  = 80
        PRIVATE_TYPES = [ :password ]
        LOGIN_STATUS  = Metasploit::Model::Login::Status # Shorter name


        # Checks if the target is BAVision Camera's web server. The login module should call this.
        #
        # @return [String] Error message if target is not a BAVision camera, otherwise FalseClass
        def check_setup
          login_uri = normalize_uri("#{uri}")
          res = send_request({'uri'=> login_uri})

          unless res && res.headers['WWW-Authenticate'] && res.headers['WWW-Authenticate'].match(/realm="IPCamera Login"/)
            return "Unable to locate \"realm=IPCamera Login\" in headers. (Is this really a BAVision camera?)"
          end

          false
        end


        # Auth to the server using digest auth
        def try_digest_auth(cred)
          login_uri = normalize_uri("#{uri}")
          res = send_request({
            'uri'        => login_uri,
            'credential' => cred,
            'DigestAuthIIS' => false,
            'headers' => {'Accept'=> '*/*'}
          })

          digest = digest_auth(cred.public, cred.private, res.headers)

          res = send_request({
            'uri' => login_uri,
            'headers' => {
              'Authorization' => digest
            }})

          if res && res.code == 200 && res.body =~ /hy\-cgi\/user\.cgi/
            return {:status => LOGIN_STATUS::SUCCESSFUL, :proof => res.body}
          end

          {:status => LOGIN_STATUS::INCORRECT, :proof => res.body}
        end

        # The Rex HTTP Digest auth is making the camera server to refuse to respond for some reason.
        # The API also fails to generate the CNONCE parameter (bug), which makes it unsuitable for
        # our needs, therefore we have our own implementation of digest auth.
        def digest_auth(user, password, response)
          nonce_count = 1
          cnonce = Digest::MD5.hexdigest("%x" % (Time.now.to_i + rand(65535)))

          i = (response['www-authenticate'] =~ /^(\w+) (.*)/)

          # The www-authenticate header does not return in the format we like,
          # so let's bail.
          unless i
            raise BavisionCamerasException, 'www-authenticate header is not in the right format'
          end

          params = {}
          $2.gsub(/(\w+)="(.*?)"/) { params[$1] = $2 }

          a_1 = "#{user}:#{params['realm']}:#{password}"
          a_2 = "GET:#{uri}"
          request_digest = ''
          request_digest << Digest::MD5.hexdigest(a_1)
          request_digest << ':' << params['nonce']
          request_digest << ':' << ('%08x' % nonce_count)
          request_digest << ':' << cnonce
          request_digest << ':' << params['qop']
          request_digest << ':' << Digest::MD5.hexdigest(a_2)

          header = []
          header << "Digest username=\"#{user}\""
          header << "realm=\"#{params['realm']}\""
          header << "qop=#{params['qop']}"
          header << "uri=\"/\""
          header << "nonce=\"#{params['nonce']}\""
          header << "nc=#{'%08x' % nonce_count}"
          header << "cnonce=\"#{cnonce}\""
          header << "response=\"#{Digest::MD5.hexdigest(request_digest)}\""

          header * ', '
        end


        # Attempts to login to the camera. This is called first.
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Result] A Result object indicating success or failure
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
            result_opts.merge!(try_digest_auth(credential))
          rescue ::Rex::ConnectionError, BavisionCamerasException => e
            # Something went wrong during login. 'e' knows what's up.
            result_opts.merge!(status: LOGIN_STATUS::UNABLE_TO_CONNECT, proof: e.message)
          end

          Result.new(result_opts)
        end

      end
    end
  end
end

