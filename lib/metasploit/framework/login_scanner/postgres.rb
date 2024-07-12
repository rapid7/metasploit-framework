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

        # @returns [Boolean] If a login is successful and this attribute is true - a Msf::Db::PostgresPR::Connection instance is used as proof,
        #   and the socket is not immediately closed
        attr_accessor :use_client_as_proof

        DEFAULT_PORT         = 5432
        DEFAULT_REALM        = 'template1'
        LIKELY_PORTS         = [ DEFAULT_PORT ]
        LIKELY_SERVICE_NAMES = [ 'postgres' ]
        PRIVATE_TYPES        = [ :password ]
        REALM_KEY            = Metasploit::Model::Realm::Key::POSTGRESQL_DATABASE

        # This method attempts a single login with a single credential against the target
        # @param credential [Credential] The credential object to attempt to login with
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
            pg_conn = Msf::Db::PostgresPR::Connection.new(db_name,credential.public,credential.private,uri,proxies)
          rescue ::RuntimeError => e
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
          rescue Rex::ConnectionError, Rex::ConnectionProxyError, Errno::ECONNRESET, Errno::EINTR, Errno::ENOTCONN, Rex::TimeoutError, EOFError, Timeout::Error => e
            result_options.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
          rescue Msf::Db::PostgresPR::AuthenticationMethodMismatch => e
            result_options.merge!({
              status: Metasploit::Model::Login::Status::INCORRECT,
              proof: e.message
            })
          end

          if pg_conn
            result_options[:status] = Metasploit::Model::Login::Status::SUCCESSFUL

            # This module no longer owns the socket so return it as proof so the calling context can perform additional operations
            # Additionally assign values to nil to avoid closing the socket etc automatically
            if use_client_as_proof
              result_options[:proof] = pg_conn
              result_options[:connection] = pg_conn.conn
            else
              pg_conn.close
            end
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
