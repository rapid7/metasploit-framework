require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      class SonicWall < HTTP

        def do_login(username, password)
          

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
