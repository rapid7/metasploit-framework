require 'metasploit/framework/login_scanner/invalid'
require 'net/ssh'

module Metasploit
  module Framework
    module LoginScanner

      class SSH
        include ActiveModel::Validations


        # @!attribute connection_timeout
        #   @return [Fixnum] The timeout in seconds for a single SSH connection
        attr_accessor :connection_timeout
        # @!attribute cred_details
        #   @return [Array] An array of hashes containing the cred
        attr_accessor :cred_details
        # @!attribute host
        #   @return [String] The IP address or hostname to connect to
        attr_accessor :host
        # @!attribute msframework
        #   @return [Framework] The Framework instance to use for Session handling
        attr_accessor :msframework
        # @!attribute msfmodule
        #   @return [Module] The Metasploit module that instantiated this object
        attr_accessor :msfmodule
        # @!attribute port
        #   @return [Fixnum] The port to connect to
        attr_accessor :port
        # @!attribute ssh_socket
        #   @return [Connection::Session] The current SSH connection
        attr_accessor :ssh_socket
        # @!attribute stop_on_success
        #   @return [Boolean] Whether the scanner should stop when it has found one working Credential
        attr_accessor :stop_on_success
        # @!attribute verbosity
        #   @return [Symbol] The verbosity level for the SSH client.
        attr_accessor :verbosity

        validates :port,
          presence: true,
          numericality: {
              only_integer:             true,
              greater_than_or_equal_to: 1,
              less_than_or_equal_to:    65535
          }

        validates :connection_timeout,
          presence: true,
          numericality: {
              only_integer:             true,
              greater_than_or_equal_to: 1
          }

        validates :verbosity,
          presence: true,
          inclusion: { in: [:debug, :info, :warn, :error, :fatal] }

        validates :stop_on_success,
          presence: true,
          inclusion: { in: [true, false] }

        validates :host, presence: true

        validates :cred_details, presence: true

        validate :host_address_must_be_valid

        validate :cred_details_must_be_array_of_hashes

        # @param attributes [Hash{Symbol => String,nil}]
        def initialize(attributes={})
          attributes.each do |attribute, value|
            public_send("#{attribute}=", value)
          end
        end

        def attempt_login(user, pass)
          ssh_socket = nil
          opt_hash = {
              :auth_methods  => ['password','keyboard-interactive'],
              :msframework   => msframework,
              :msfmodule     => msfmodule,
              :port          => port,
              :disable_agent => true,
              :password      => pass,
              :config        => false,
              :verbose       => verbosity
          }

          begin
            ::Timeout.timeout(connection_timeout) do
              ssh_socket = Net::SSH.start(
                  host,
                  user,
                  opt_hash
              )
            end
          rescue Rex::ConnectionError, Rex::AddressInUse
            return :connection_error
          rescue Net::SSH::Disconnect, ::EOFError
            return :connection_disconnect
          rescue ::Timeout::Error
            return :connection_disconnect
          rescue Net::SSH::Exception
            return [:fail,nil] # For whatever reason. Can't tell if passwords are on/off without timing responses.
          end

          if ssh_socket
            proof = gather_proof
            create_session(proof,user,pass)
            [:success, proof]
          else
            [:fail, nil]
          end

        end

        def scan!
          valid!

        end

        # @raise [Metasploit::Framework::LoginScanner::Invalid] if the attributes are not valid on the scanner
        def valid!
          unless valid?
            raise Metasploit::Framework::LoginScanner::Invalid.new(self)
          end
        end

        private

        def create_session(proof,user,pass)
          conn = Net::SSH::CommandStream.new(ssh_socket, '/bin/sh', true)

          datastore_opts = {
              'USERPASS_FILE' => nil,
              'USER_FILE'     => nil,
              'PASS_FILE'     => nil,
              'USERNAME'      => user,
              'PASSWORD'      => pass
          }
          
          session = Msf::Sessions::CommandShell.new(conn.lsock)
          session.info = "SSH: #{user}:#{pass} (#{host}:#{port})"

          # Set module details on the session if we have them
          if msfmodule
            session.set_from_exploit(msfmodule)
            session.exploit_datastore.merge!(datastore_opts)
          end

          # Register the new session
          if msframework
            msframework.sessions.register(session)
          end

          # Set the session platform
          case proof
            when /Linux/
              session.platform = "linux"
            when /Darwin/
              session.platform = "osx"
            when /SunOS/
              session.platform = "solaris"
            when /BSD/
              session.platform = "bsd"
            when /HP-UX/
              session.platform = "hpux"
            when /AIX/
              session.platform = "aix"
            when /Win32|Windows/
              session.platform = "windows"
            when /Unknown command or computer name/
              session.platform = "cisco-ios"
          end
        end

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

        def host_address_must_be_valid
          unless host.kind_of? String
            errors.add(:host, "must be a string")
          end
          begin
            ::Rex::Socket.getaddress(value, true)
          rescue
            errors.add(:host, "could not be resolved")
          end
        end

        def cred_details_must_be_array_of_hashes
          if cred_details.kind_of? Array
            cred_details.each do |detail|
              validate_cred_detail(detail)
            end
          else
            errors.add(:cred_details, "must be an array")
          end
        end

        def validate_cred_detail(detail)
          if detail.kind_of? Hash
            if detail.has_key? :public
              unless detail[:public].kind_of? String
                errors.add(:cred_details, "has invalid element, invalid public component #{detail.inspect}")
              end
            else
              errors.add(:cred_details, "has invalid element, missing public component #{detail.inspect}")
            end
            if detail.has_key? :private
              unless detail[:private].kind_of? String
                errors.add(:cred_details, "has invalid element, invalid private component #{detail.inspect}")
              end
            else
              errors.add(:cred_details, "has invalid element, missing private component #{detail.inspect}")
            end
          else
            errors.add(:cred_details, "has invalid element #{detail.inspect}")
          end
        end

      end

    end
  end
end
