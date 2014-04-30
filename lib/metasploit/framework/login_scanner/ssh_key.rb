require 'net/ssh'
require 'metasploit/framework/login_scanner/base'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with the Secure Shell protocol and PKI.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results. In this case it is expecting
      # SSH private keys for the private credential.
      class SSHKey
        include Metasploit::Framework::LoginScanner::Base

        #
        # CONSTANTS
        #

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

        validates :verbosity,
                  presence: true,
                  inclusion: { in: VERBOSITIES }


        # This method attempts a single login with a single credential against the target
        # @param credential [Credential] The credential object to attmpt to login with
        # @return [Metasploit::Framework::LoginScanner::Result] The LoginScanner Result object
        def attempt_login(credential)
          ssh_socket = nil
          opt_hash = {
              :auth_methods  => ['publickey'],
              :port          => port,
              :disable_agent => true,
              :key_data      => credential.private,
              :config        => false,
              :verbose       => verbosity,
              :proxies       => proxies
          }

          result_options = {
              private: credential.private,
              public: credential.public,
              realm: nil
          }
          begin
            ::Timeout.timeout(connection_timeout) do
              ssh_socket = Net::SSH.start(
                  host,
                  credential.public,
                  opt_hash
              )
            end
          rescue ::EOFError, Net::SSH::Disconnect, Rex::AddressInUse, Rex::ConnectionError, ::Timeout::Error
            result_options.merge!( proof: nil, status: :connection_error)
          rescue Net::SSH::Exception
            result_options.merge!( proof: nil, status: :failed)
          end

          unless result_options.has_key? :status
            if ssh_socket
              proof = gather_proof
              result_options.merge!( proof: proof, status: :success)
            else
              result_options.merge!( proof: nil, status: :failed)
            end
          end

          ::Metasploit::Framework::LoginScanner::Result.new(result_options)

        end

        private

        # This method attempts to gather proof that we successfuly logged in.
        # @return [String] The proof of a connection, May be empty.
        def gather_proof
          proof = ''
          begin
            Timeout.timeout(5) do
              proof = ssh_socket.exec!("id\n").to_s
              if(proof =~ /id=/)
                proof << ssh_socket.exec!("uname -a\n").to_s
              else
                # Cisco IOS
                if proof =~ /Unknown command or computer name/
                  proof = ssh_socket.exec!("ver\n").to_s
                else
                  proof << ssh_socket.exec!("help\n?\n\n\n").to_s
                end
              end
            end
          rescue ::Exception
          end
          proof
        end

        def set_sane_defaults
          self.connection_timeout = 30 if self.connection_timeout.nil?
          self.verbosity = :fatal if self.verbosity.nil?
        end

      end

    end
  end
end
