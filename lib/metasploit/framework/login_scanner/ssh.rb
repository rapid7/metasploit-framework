require 'net/ssh'
require 'metasploit/framework/login_scanner/base'
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

        validates :verbosity,
          presence: true,
          inclusion: { in: VERBOSITIES }

        # (see {Base#attempt_login})
        # @note The caller *must* close {#ssh_socket}
        def attempt_login(credential)
          self.ssh_socket = nil
          factory = Rex::Socket::SSHFactory.new(framework,framework_module, proxies)
          opt_hash = {
            :port            => port,
            :use_agent       => false,
            :config          => false,
            :verbose         => verbosity,
            :proxy           => factory,
            :non_interactive => true,
            :verify_host_key => :never
          }
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
          rescue OpenSSL::Cipher::CipherError, ::EOFError, Net::SSH::Disconnect, Rex::ConnectionError, ::Timeout::Error => e
            result_options.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
          rescue Net::SSH::Exception
            result_options.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: e)
          end

          unless result_options.has_key? :status
            if ssh_socket
              proof = gather_proof
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

        # This method attempts to gather proof that we successfuly logged in.
        # @return [String] The proof of a connection, May be empty.
        def gather_proof
          proof = ''
          begin
            Timeout.timeout(5) do
              proof = ssh_socket.exec!("id\n").to_s
              if (proof =~ /id=/)
                proof << ssh_socket.exec!("uname -a\n").to_s
                if (proof =~/JUNOS /)
                  # We're in the SSH shell for a Juniper JunOS, we can pull the version from the cli
                  # line 2 is hostname, 3 is model, 4 is the Base OS version
                  proof = ssh_socket.exec!("cli show version\n").split("\n")[2..4].join(", ").to_s
                end
              else
                # Cisco IOS
                if proof =~ /Unknown command or computer name/
                  proof = ssh_socket.exec!("ver\n").to_s
                # Juniper ScreenOS
                elsif proof =~ /unknown keyword/
                  proof = ssh_socket.exec!("get chassis\n").to_s
                # Juniper JunOS CLI
                elsif proof =~ /unknown command: id/
                  proof = ssh_socket.exec!("show version\n").split("\n")[2..4].join(", ").to_s
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
          self.port = DEFAULT_PORT if self.port.nil?
          self.verbosity = :fatal if self.verbosity.nil?
        end

        public

        def get_platform(proof)
          case proof
          when /Linux/
            'linux'
          when /Darwin/
            'osx'
          when /SunOS/
            'solaris'
          when /BSD/
            'bsd'
          when /HP-UX/
            'hpux'
          when /AIX/
            'aix'
          when /Win32|Windows/
            'windows'
          when /Unknown command or computer name/
            'cisco-ios'
          when /unknown keyword/ # ScreenOS
            'juniper'
          when /JUNOS Base OS/ #JunOS
            'juniper'
          end
        end

      end

    end
  end
end
