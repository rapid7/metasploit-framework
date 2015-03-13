require 'metasploit/framework/login_scanner/base'
require 'postgres_msf'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with PostgreSQL database servers.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class Postgres
        include Metasploit::Framework::LoginScanner::Base

        DEFAULT_PORT         = 5432
        DEFAULT_REALM        = 'template1'
        LIKELY_PORTS         = [ DEFAULT_PORT ]
        LIKELY_SERVICE_NAMES = [ 'postgres' ]
        PRIVATE_TYPES        = [ :password ]
        REALM_KEY            = Metasploit::Model::Realm::Key::POSTGRESQL_DATABASE

        # This method attempts a single login with a single credential against the target
        # @param credential [Credential] The credential object to attmpt to login with
        # @return [Metasploit::Framework::LoginScanner::Result] The LoginScanner Result object
        def attempt_login(credential)
          result_options = {
              credential: credential,
              host: host,
              port: port,
              protocol: 'tcp',
              service_name: 'postgres'
          }

          db_name = credential.realm || 'template1'

          if ::Rex::Socket.is_ipv6?(host)
            uri = "tcp://[#{host}]:#{port}"
          else
            uri = "tcp://#{host}:#{port}"
          end

          pg_conn = nil

          begin
            pg_conn = Msf::Db::PostgresPR::Connection.new(db_name,credential.public,credential.private,uri)
          rescue RuntimeError => e
            case e.to_s.split("\t")[1]
              when "C3D000"
                result_options.merge!({
                  status: Metasploit::Model::Login::Status::INCORRECT,
                  proof: "C3D000, Creds were good but database was bad"
                })
              when "C28000", "C28P01"
                result_options.merge!({
                    status: Metasploit::Model::Login::Status::INCORRECT,
                    proof: "Invalid username or password"
                })
              else
                result_options.merge!({
                    status: Metasploit::Model::Login::Status::INCORRECT,
                    proof: e.message
                })
            end
          rescue Rex::ConnectionError, EOFError, Timeout::Error => e
            result_options.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
          rescue Msf::Db::PostgresPR::AuthenticationMethodMismatch => e
            result_options.merge!({
              status: Metasploit::Model::Login::Status::INCORRECT,
              proof: e.message
            })
          end

          if pg_conn
            pg_conn.close
            result_options[:status] = Metasploit::Model::Login::Status::SUCCESSFUL
          else
            result_options[:status] = Metasploit::Model::Login::Status::INCORRECT
          end

          ::Metasploit::Framework::LoginScanner::Result.new(result_options)
        end
      end

      def set_sane_defaults
        self.connection_timeout ||= 30
        self.port               ||= DEFAULT_PORT
      end

    end
  end
end
