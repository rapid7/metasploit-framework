require 'metasploit/framework'
require 'metasploit/framework/tcp/client'
require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'
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
          ADMINISTRATOR = "Administrator"
          # Guest access means our creds were accepted but the logon
          # session is not associated with a real user account.
          GUEST = "Guest"
        end

        CAN_GET_SESSION      = true
        DEFAULT_REALM        = 'WORKSTATION'
        LIKELY_PORTS         = [ 445 ]
        LIKELY_SERVICE_NAMES = [ "smb" ]
        PRIVATE_TYPES        = [ :password, :ntlm_hash ]
        REALM_KEY            = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN

        module StatusCodes
          CORRECT_CREDENTIAL_STATUS_CODES = [
            "STATUS_ACCOUNT_DISABLED",
            "STATUS_ACCOUNT_EXPIRED",
            "STATUS_ACCOUNT_RESTRICTION",
            "STATUS_INVALID_LOGON_HOURS",
            "STATUS_INVALID_WORKSTATION",
            "STATUS_LOGON_TYPE_NOT_GRANTED",
            "STATUS_PASSWORD_EXPIRED",
            "STATUS_PASSWORD_MUST_CHANGE",
          ].freeze.map(&:freeze)
        end

        # @!attribute dispatcher
        #   @return [RubySMB::Dispatcher::Socket]
        attr_accessor :dispatcher

        # If login is successul and {Result#access_level} is not set
        # then arbitrary credentials are accepted. If it is set to
        # Guest, then arbitrary credentials are accepted, but given
        # Guest permissions.
        #
        # @param domain [String] Domain to authenticate against. Use an
        #   empty string for local accounts.
        # @return [Result]
        def attempt_bogus_login(domain)
          if defined?(@result_for_bogus)
            return @result_for_bogus
          end
          cred = Credential.new(
            public: Rex::Text.rand_text_alpha(8),
            private: Rex::Text.rand_text_alpha(8),
            realm: domain
          )
          @result_for_bogus = attempt_login(cred)
        end


        # (see Base#attempt_login)
        def attempt_login(credential)

          begin
            connect
          rescue ::Rex::ConnectionError => e
            result = Result.new(
              credential:credential,
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
            realm       = (credential.realm   || "").force_encoding('UTF-8')
            username    = (credential.public  || "").force_encoding('UTF-8')
            password    = (credential.private || "").force_encoding('UTF-8')
            client      = RubySMB::Client.new(self.dispatcher, username: username, password: password, domain: realm)
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
              rescue Exception => e
                client.tree_connect("\\\\#{host}\\IPC$")
              end
            end

            case status_code.name
              when 'STATUS_SUCCESS', 'STATUS_PASSWORD_MUST_CHANGE', 'STATUS_PASSWORD_EXPIRED'
                status = Metasploit::Model::Login::Status::SUCCESSFUL
              when 'STATUS_ACCOUNT_LOCKED_OUT'
                status = Metasploit::Model::Login::Status::LOCKED_OUT
              when 'STATUS_LOGON_FAILURE', 'STATUS_ACCESS_DENIED'
                status = Metasploit::Model::Login::Status::INCORRECT
              when *StatusCodes::CORRECT_CREDENTIAL_STATUS_CODES
                status = Metasploit::Model::Login::Status::DENIED_ACCESS
              else
                status = Metasploit::Model::Login::Status::INCORRECT
            end
          rescue ::Rex::ConnectionError, Errno::EINVAL, RubySMB::Error::NetBiosSessionService => e
            status = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
            proof = e
          rescue RubySMB::Error::UnexpectedStatusCode => e
            status = Metasploit::Model::Login::Status::INCORRECT
          ensure
            client.disconnect! if client
          end

          if status == Metasploit::Model::Login::Status::SUCCESSFUL && credential.public.empty?
            access_level ||= AccessLevels::GUEST
          end

          result = Result.new(credential: credential, status: status, proof: proof, access_level: access_level)
          result.host         = host
          result.port         = port
          result.protocol     = 'tcp'
          result.service_name = 'smb'
          result
        end

        def connect
          disconnect
          self.sock       = super
          self.dispatcher = RubySMB::Dispatcher::Socket.new(self.sock)
        end

        def set_sane_defaults
          self.connection_timeout           = 10 if self.connection_timeout.nil?
          self.max_send_size                = 0 if self.max_send_size.nil?
          self.send_delay                   = 0 if self.send_delay.nil?
        end

      end
    end
  end
end

