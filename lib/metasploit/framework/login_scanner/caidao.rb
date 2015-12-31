require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # Chinese Caidao login scanner
      class Caidao < HTTP
        # Inherit LIKELY_PORTS, LIKELY_SERVICE_NAMES, and REALM_KEY from HTTP
        DEFAULT_PORT       = 80
        PRIVATE_TYPES      = [ :password ]

        def set_sane_defaults
          self.method = "POST" if self.method.nil?
        end

        def attempt_login(credential)
          result_opts = {
            credential:  credential,
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
            status = try_login(credential)
            result_opts.merge!(status)
          rescue ::EOFError, Errno::ETIMEDOUT, Errno::ECONNRESET, Rex::ConnectionError, OpenSSL::SSL::SSLError, ::Timeout::Error => e
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
          end
          Result.new(result_opts)
        end

        def try_login(credential)
          cli = Rex::Proto::Http::Client.new(host, port, { 'Msf' => framework, 'MsfExploit' => framework_module }, ssl, ssl_version, proxies)
          configure_http_client(cli)
          cli.connect
          flag = Rex::Text.rand_text_alphanumeric(4)
          lmark = Rex::Text.rand_text_alphanumeric(4)
          rmark = Rex::Text.rand_text_alphanumeric(4)

          case self.uri
          when /php$/mi
            payload = "$_=\"#{flag}\";echo \"#{lmark}\".$_.\"#{rmark}\";"
          when /asp$/mi
            payload = 'execute("response.write(""'
            payload << "#{lmark}"
            payload << '""):response.write(""'
            payload << "#{flag}"
            payload << '""):response.write(""'
            payload << "#{rmark}"
            payload << '""):response.end")'
          when /aspx$/mi
            payload = "Response.Write(\"#{lmark}\");"
            payload << "Response.Write(\"#{flag}\");"
            payload << "Response.Write(\"#{rmark}\")"
          else
            print_error("Backdoor type is not support")
            return
          end

          req = cli.request_cgi({
            'method'    => method,
            'uri'       => uri,
            'data'      => "#{credential.private}=#{payload}"
          })
          res = cli.send_recv(req)

          if res && res.code == 200 && res.body.to_s.include?("#{lmark}#{flag}#{rmark}")
            return { :status => Metasploit::Model::Login::Status::SUCCESSFUL, :proof => res.body }
          end

          { :status => Metasploit::Model::Login::Status::INCORRECT, :proof => res.body }
        end
      end
    end
  end
end
