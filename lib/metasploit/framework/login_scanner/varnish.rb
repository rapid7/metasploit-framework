require 'metasploit/framework/tcp/client'
require 'metasploit/framework/varnish/client'
require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with Varnish CLI.

      class VarnishCLI
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket
        include Metasploit::Framework::Tcp::Client
        include Metasploit::Framework::Varnish::Client

        DEFAULT_PORT         = 6082
        LIKELY_PORTS         = [ DEFAULT_PORT ]
        LIKELY_SERVICE_NAMES = [ 'varnishcli' ]
        PRIVATE_TYPES        = [ :password ]
        REALM_KEY           = nil

        def report_varnish_server
          report_service(host: host, port: port, name: 'VarnishCLI', proto: 'tcp', workspace_id: myworkspace_id, parents: [ ssl ? :ssl : :tcp ])
        end

        def attempt_login(credential)
          begin
            connect
            success = login(credential.private)
            close_session
            disconnect
          rescue RuntimeError => e
            return {:status => Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, :proof => e.message}
          rescue Rex::ConnectionError, EOFError, Timeout::Error
            status = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
          end
          status ||= (success == true) ? Metasploit::Model::Login::Status::SUCCESSFUL : Metasploit::Model::Login::Status::INCORRECT

          result = Result.new(credential: credential, status: status)
          result.host         = host
          result.port         = port
          result.protocol     = 'tcp'
          result.service_name = 'varnishcli'
          result.ssl = ssl

          report_varnish_server if should_report_service?(result)

          result
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
