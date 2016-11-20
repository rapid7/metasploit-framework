require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with Varnish CLI.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class VarnishCLI
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket
        include Metasploit::Framework::Tcp::Client

        DEFAULT_PORT         = 6082
        LIKELY_PORTS         = [ DEFAULT_PORT ]
        LIKELY_SERVICE_NAMES = [ 'varnishcli' ]
        PRIVATE_TYPES        = [ :password ]
        REALM_KEY           = nil

        def attempt_login(credential)
          result_opts = {
            credential: credential,
            host: host,
            port: port,
            service_name: 'varnishcli',
            protocol: 'tcp',
            max_send_size: datastore['TCP::max_send_size'],
            send_delay: datastore['TCP::send_delay']
          }
          begin
            disconnect if self.sock
            connect
            sock.put("auth #{Rex::Text.rand_text_alphanumeric(3)}\n") # Cause a login fail to get the challenge
            res = sock.get_once(-1,3) # grab challenge
            if res && res =~ /107 \d+\s\s\s\s\s\s\n(\w+)\n\nAuthentication required./ # 107 auth
              challenge = $1
              response = challenge + "\n"
              response << credential.private + "\n"
              response << challenge + "\n"
              #secret = pass + "\n" # newline is needed
              #response = challenge + "\n" + secret + challenge + "\n"
              response = Digest::SHA256.hexdigest(response)
              sock.put("auth #{response}\n")
              res = sock.get_once(-1,3)
              if res && res =~ /107 \d+/ # 107 auth
                result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: res)
              elsif res.nil?
                result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: 'No response')
              elsif res =~ /200 \d+/ # 200 ok
                result_opts.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL, proof: res)
              end
            elsif res && res =~ /Varnish Cache CLI 1.0/
              result_opts.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL, proof: 'No Authentication Required')
            else
              result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: 'Unknown Response')
            end
            disconnect
          rescue ::EOFError, Errno::ECONNRESET, Rex::ConnectionError, Rex::ConnectionTimeout, ::Timeout::Error
            result_options[:status] = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
          end
          Result.new(result_opts)
        end

        def set_sane_defaults
          self.connection_timeout ||= 30
          self.port               ||= DEFAULT_PORT
          self.max_send_size      ||= 0
          self.send_delay         ||= 0
        end

      end
    end
  end
end
