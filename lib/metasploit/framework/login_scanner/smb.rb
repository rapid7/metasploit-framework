require 'metasploit/framework'
require 'metasploit/framework/tcp/client'
require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'
require 'metasploit/framework/login_scanner/kerberos'
require 'ruby_smb'

module Metasploit
  module Framework
    module LoginScanner
      # This is the LoginScanner class for dealing with the Server Messaging
      # Block protocol.
      class SMB
        include Metasploit::Framework::Tcp::Client
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket

        # Constants to be used in {Result#access_level}
        module AccessLevels
          # Administrative access. For SMB, this is defined as being
          # able to successfully Tree Connect to the `ADMIN$` share.
          # This definition is not without its problems, but suffices to
          # conclude that such a user will most likely be able to use
          # psexec.
          ADMINISTRATOR = 'Administrator'.freeze
          # Guest access means our creds were accepted but the logon
          # session is not associated with a real user account.
          GUEST = 'Guest'.freeze
        end

        CAN_GET_SESSION = true
        DEFAULT_REALM = 'WORKSTATION'.freeze
        LIKELY_PORTS = [ 445 ].freeze
        LIKELY_SERVICE_NAMES = [ 'smb' ].freeze
        PRIVATE_TYPES = %i[password ntlm_hash].freeze
        REALM_KEY = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN

        module StatusCodes
          CORRECT_CREDENTIAL_STATUS_CODES = [
            WindowsError::NTStatus::STATUS_ACCOUNT_DISABLED,
            WindowsError::NTStatus::STATUS_ACCOUNT_EXPIRED,
            WindowsError::NTStatus::STATUS_ACCOUNT_RESTRICTION,
            WindowsError::NTStatus::STATUS_INVALID_LOGON_HOURS,
            WindowsError::NTStatus::STATUS_INVALID_WORKSTATION,
            WindowsError::NTStatus::STATUS_LOGON_TYPE_NOT_GRANTED,
            WindowsError::NTStatus::STATUS_PASSWORD_EXPIRED,
            WindowsError::NTStatus::STATUS_PASSWORD_MUST_CHANGE,
          ].freeze
        end

        # @returns [Array[Integer]] The SMB versions to negotiate
        attr_accessor :versions

        # @returns [Boolean] By default the client uses encryption even if it is not required by the server. Disable this by setting always_encrypt to false
        attr_accessor :always_encrypt

        # @!attribute dispatcher
        #   @return [RubySMB::Dispatcher::Socket]
        attr_accessor :dispatcher

        # @!attribute kerberos_authenticator_factory
        #   @return [Func<username, password, realm> : Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::SMB]
        #     A factory method for creating a kerberos authenticator
        attr_accessor :kerberos_authenticator_factory

        # @returns [Boolean] If a login is successful and this attribute is true - a RubySMB::Client instance is used as proof,
        #   and the socket is not immediately closed
        attr_accessor :use_client_as_proof

        # If login is successful and {Result#access_level} is not set
        # then arbitrary credentials are accepted. If it is set to
        # Guest, then arbitrary credentials are accepted, but given
        # Guest permissions.
        #
        # @param domain [String] Domain to authenticate against. Use an
        #   empty string for local accounts.
        # @return [Result]
        def attempt_bogus_login(domain)
          if defined?(@attempt_bogus_login)
            return @attempt_bogus_login
          end

          cred = Credential.new(
            public: Rex::Text.rand_text_alpha(8),
            private: Rex::Text.rand_text_alpha(8),
            realm: domain
          )
          @attempt_bogus_login = attempt_login(cred)
        end

        # (see Base#attempt_login)
        def attempt_login(credential)
          begin
            connect
          rescue ::Rex::ConnectionError => e
            result = Result.new(
              credential: credential,
              status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT,
              proof: e,
              host: host,
              port: port,
              protocol: 'tcp',
              service_name: 'smb'
            )
            return result
          end
          proof = nil

          begin
            realm = (credential.realm || '').dup.force_encoding('UTF-8')
            username = (credential.public || '').dup.force_encoding('UTF-8')
            password = (credential.private || '').dup.force_encoding('UTF-8')
            client = RubySMB::Client.new(
               dispatcher,
               username: username,
               password: password,
               domain: realm,
               smb1: versions.include?(1),
               smb2: versions.include?(2),
               smb3: versions.include?(3),
               always_encrypt: always_encrypt
            )

            if kerberos_authenticator_factory
              client.extend(Msf::Exploit::Remote::SMB::Client::KerberosAuthentication)
              client.kerberos_authenticator = kerberos_authenticator_factory.call(username, password, realm)
            end

            status_code = client.login

            if status_code == WindowsError::NTStatus::STATUS_SUCCESS
              # Windows SMB will return an error code during Session
              # Setup, but nix Samba requires a Tree Connect. Try admin$
              # first, since that will tell us if this user has local
              # admin access. Fall back to IPC$ which should be accessible
              # to any user with valid creds.
              begin
                tree = client.tree_connect("\\\\#{host}\\admin$")
                # Check to make sure we can write a file to this dir
                if tree.permissions.add_file == 1
                  access_level = AccessLevels::ADMINISTRATOR
                end
              rescue StandardError => _e
                client.tree_connect("\\\\#{host}\\IPC$")
              end
            end

            case status_code
            when WindowsError::NTStatus::STATUS_SUCCESS, WindowsError::NTStatus::STATUS_PASSWORD_MUST_CHANGE, WindowsError::NTStatus::STATUS_PASSWORD_EXPIRED
              status = Metasploit::Model::Login::Status::SUCCESSFUL
              # This module no long owns the socket, return it as proof so the calling context can perform additional operations
              # Additionally assign values to nil to avoid closing the socket etc automatically
              if use_client_as_proof
                proof = client
                connection = self.sock
                client = nil
                self.sock = nil
                self.dispatcher = nil
              end
            when WindowsError::NTStatus::STATUS_ACCOUNT_LOCKED_OUT
              status = Metasploit::Model::Login::Status::LOCKED_OUT
            when WindowsError::NTStatus::STATUS_LOGON_FAILURE, WindowsError::NTStatus::STATUS_ACCESS_DENIED
              status = Metasploit::Model::Login::Status::INCORRECT
            when *StatusCodes::CORRECT_CREDENTIAL_STATUS_CODES
              status = Metasploit::Model::Login::Status::DENIED_ACCESS
            else
              status = Metasploit::Model::Login::Status::INCORRECT
            end
          rescue ::Rex::ConnectionError, Errno::EINVAL, RubySMB::Error::NetBiosSessionService, RubySMB::Error::NegotiationFailure, RubySMB::Error::CommunicationError  => e
            status = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
            proof = e
          rescue RubySMB::Error::UnexpectedStatusCode => _e
            status = Metasploit::Model::Login::Status::INCORRECT
          rescue Rex::Proto::Kerberos::Model::Error::KerberosError => e
            status = Metasploit::Framework::LoginScanner::Kerberos.login_status_for_kerberos_error(e)
            proof = e
          rescue RubySMB::Error::RubySMBError => _e
            status = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
            proof = e
          ensure
            client.disconnect! if client
          end

          if status == Metasploit::Model::Login::Status::SUCCESSFUL && credential.public.empty?
            access_level ||= AccessLevels::GUEST
          end

          result = Result.new(credential: credential,
                              status: status,
                              proof: proof,
                              access_level: access_level,
                              connection: connection)
          result.host = host
          result.port = port
          result.protocol = 'tcp'
          result.service_name = 'smb'
          result
        end

        def connect
          disconnect
          self.sock = super
          self.dispatcher = RubySMB::Dispatcher::Socket.new(sock)
        end

        def set_sane_defaults
          self.connection_timeout = 10 if connection_timeout.nil?
          self.max_send_size = 0 if max_send_size.nil?
          self.send_delay = 0 if send_delay.nil?
          self.always_encrypt = true if always_encrypt.nil?
          self.versions = ::Rex::Proto::SMB::SimpleClient::DEFAULT_VERSIONS if versions.nil?
        end

      end
    end
  end
end
