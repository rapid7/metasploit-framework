require 'net/ssh'
require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/ssh/platform'
require 'rex/socket/ssh_factory'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with the Secure Shell protocol.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      #
      class SSH
        include Metasploit::Framework::LoginScanner::Base
        include Msf::Exploit::Remote::SSH
        #
        # CONSTANTS
        #

        CAN_GET_SESSION      = true
        DEFAULT_PORT         = 22
        LIKELY_PORTS         = [ DEFAULT_PORT ]
        LIKELY_SERVICE_NAMES = [ 'ssh' ]
        PRIVATE_TYPES        = [ :password, :ssh_key ]
        REALM_KEY            = nil

        VERBOSITIES = [
            :debug,
            :info,
            :warn,
            :error,
            :fatal
        ]
        # @!attribute ssh_socket
        #   @return [Net::SSH::Connection::Session] The current SSH connection
        attr_accessor :ssh_socket
        # @!attribute verbosity
        #   The verbosity level for the SSH client.
        #
        #   @return [Symbol] An element of {VERBOSITIES}.
        attr_accessor :verbosity
        # @!attribute skip_gather_proof
        #   @return [Boolean] Whether to skip calling gather_proof
        attr_accessor :skip_gather_proof

        validates :verbosity,
          presence: true,
          inclusion: { in: VERBOSITIES }

        # (see {Base#attempt_login})
        # @note The caller *must* close {#ssh_socket}
        def attempt_login(credential)
          self.ssh_socket = nil
          opt_hash = ssh_client_defaults.merge({
            :port            => port,
            :verbose         => verbosity
          })
          case credential.private_type
          when :password, nil
            opt_hash.update(
              :auth_methods  => ['password','keyboard-interactive'],
              :password      => credential.private,
            )
          when :ssh_key
            opt_hash.update(
              :auth_methods  => ['publickey'],
              :key_data      => credential.private,
            )
          end

          result_options = {
            credential: credential
          }
          begin
            ::Timeout.timeout(connection_timeout) do
              self.ssh_socket = Net::SSH.start(
                host,
                credential.public,
                opt_hash
              )
            end
          rescue OpenSSL::Cipher::CipherError, ::EOFError, Net::SSH::Disconnect, Rex::ConnectionError, ::Timeout::Error, Errno::ECONNRESET, Errno::EPIPE => e
            result_options.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
          rescue Net::SSH::Exception => e
            status = Metasploit::Model::Login::Status::INCORRECT
            status = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT if e.message.split("\n").first == 'could not settle on kex algorithm'

            result_options.merge!(status: status, proof: e)
          end

          unless result_options.has_key? :status
            if ssh_socket
              begin
                proof = gather_proof unless skip_gather_proof
              rescue StandardError => e
                elog('Failed to gather SSH proof', error: e)
                proof = nil
              end
              result_options.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL, proof: proof)
            else
              result_options.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: nil)
            end
          end

          result = ::Metasploit::Framework::LoginScanner::Result.new(result_options)
          result.host         = host
          result.port         = port
          result.protocol     = 'tcp'
          result.service_name = 'ssh'
          result
        end

        private

        # This method attempts to gather proof that we successfully logged in.
        # @return [String] The proof of a connection, May be empty.
        def gather_proof
          Metasploit::Framework::Ssh::Platform.get_platform_info(ssh_socket)
        end

        def set_sane_defaults
          self.connection_timeout = 30 if self.connection_timeout.nil?
          self.port = DEFAULT_PORT if self.port.nil?
          self.verbosity = :fatal if self.verbosity.nil?
        end

        public

        def get_platform(proof)
          Metasploit::Framework::Ssh::Platform.get_platform_from_info(proof)
        end
      end
    end
  end
end
