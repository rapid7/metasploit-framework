require 'snmp'
require 'metasploit/framework/login_scanner'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with SNMP.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class SNMP
        include ActiveModel::Validations

        # @!attribute connection_timeout
        #   @return [Fixnum] The timeout in seconds for a single SSH connection
        attr_accessor :connection_timeout
        # @!attribute cred_details
        #   @return [Array] An array of Credential objects
        attr_accessor :cred_details
        # @!attribute successes
        #   @return [Array] Array of of result objects that failed
        attr_accessor :failures
        # @!attribute host
        #   @return [String] The IP address or hostname to connect to
        attr_accessor :host
        # @!attribute port
        #   @return [Fixnum] The port to connect to
        attr_accessor :port
        # @!attribute proxies
        #   @return [String] The proxy directive to use for the socket
        attr_accessor :proxies
        # @!attribute ssh_socket
        #   @return [Net::SSH::Connection::Session] The current SSH connection

        attr_accessor :stop_on_success
        # @!attribute successes
        #   @return [Array] Array of results that successfully logged in
        attr_accessor :successes


        validates :connection_timeout,
                  presence: true,
                  numericality: {
                      only_integer:             true,
                      greater_than_or_equal_to: 1
                  }

        validates :cred_details, presence: true

        validates :host, presence: true

        validates :port,
                  presence: true,
                  numericality: {
                      only_integer:             true,
                      greater_than_or_equal_to: 1,
                      less_than_or_equal_to:    65535
                  }

        validates :stop_on_success,
                  inclusion: { in: [true, false] }

        validate :host_address_must_be_valid

        validate :validate_cred_details

        # @param attributes [Hash{Symbol => String,nil}]
        def initialize(attributes={})
          attributes.each do |attribute, value|
            public_send("#{attribute}=", value)
          end
          self.successes= []
          self.failures=[]
        end

        # This method attempts a single login with a single credential against the target
        # @param credential [Credential] The credential object to attmpt to login with
        # @return [Metasploit::Framework::LoginScanner::Result] The LoginScanner Result object
        def attempt_login(credential)
          result_options = {
              private: nil,
              public: credential.public,
              realm: nil
          }

          write_access = false

          [:SNMPv1, :SNMPv2c].each do |version|
            snmp_client = ::SNMP::Manager.new(
                :Host      => host,
                :Port      => port,
                :Community => credential.public,
                :Version => version,
                :Timeout => 1,
                :Retries => 2,
                :Transport => ::SNMP::RexUDPTransport,
                :Socket => ::Rex::Socket::Udp.create
            )

            result_options[:proof] = test_read_access(snmp_client)
            if result_options[:proof].nil?
              result_options[:status] = :failed
            else
              result_options[:status] = :success
              if has_write_access?(snmp_client, result_options[:proof])
                result_options[:access_level] = "read-write"
              else
                result_options[:access_level] = "read-only"
              end
            end
          end

          ::Metasploit::Framework::LoginScanner::Result.new(result_options)
        end

        # This method runs all the login attempts against the target.
        # It calls {attempt_login} once for each credential.
        # Results are stored in {successes} and {failures}
        # @return [void] There is no valid return value for this method
        # @yield [result]
        # @yieldparam result [Metasploit::Framework::LoginScanner::Result] The LoginScanner Result object for the attempt
        # @yieldreturn [void]
        def scan!
          valid!
          cred_details.each do |credential|
            result = attempt_login(credential)
            result.freeze

            yield result if block_given?

            if result.success?
              successes << result
              break if stop_on_success
            else
              failures << result
            end
          end
        end

        # @raise [Metasploit::Framework::LoginScanner::Invalid] if the attributes are not valid on the scanner
        def valid!
          unless valid?
            raise Metasploit::Framework::LoginScanner::Invalid.new(self)
          end
        end

        private

        # This method validates that the host address is both
        # of a valid type and is resolveable.
        # @return [void]
        def host_address_must_be_valid
          unless host.kind_of? String
            errors.add(:host, "must be a string")
          end
          begin
            resolved_host = ::Rex::Socket.getaddress(host, true)
            if host =~ /^\d{1,3}(\.\d{1,3}){1,3}$/
              unless host =~ Rex::Socket::MATCH_IPV4
                errors.add(:host, "could not be resolved")
              end
            end
            host = resolved_host
          rescue
            errors.add(:host, "could not be resolved")
          end
        end

        # This method takes an snmp client and tests whether
        # it has read access to the remote system. It checks
        # the sysDescr oid to use as proof
        # @param snmp_client [SNMP::Manager] The SNMP client to use
        # @return [String, nil] Returns a string if successful, nil if failed
        def test_read_access(snmp_client)
          proof = nil
          begin
            resp = snmp_client.get("sysDescr.0")
            resp.each_varbind { |var| proof = var.value }
          rescue RuntimeError
            proof = nil
          end
          proof
        end

        # This method takes an snmp client and tests whether
        # it has write access to the remote system. It sets the
        # the sysDescr oid to the same value we already read.
        # @param snmp_client [SNMP::Manager] The SNMP client to use
        # @param value [String] the value to set sysDescr back to
        # @return [Boolean] Returns true or false for if we have write access
        def has_write_access?(snmp_client, value)
          var_bind = ::SNMP::VarBind.new("1.3.6.1.2.1.1.1.0", ::SNMP::OctetString.new(value))
          begin
            resp = snmp_client.set(var_bind)
            if resp.error_status == :noError
              return true
            end
          rescue RuntimeError
            return false
          end

        end


        # This method validates that the credentials supplied
        # are all valid.
        # @return [void]
        def validate_cred_details
          if cred_details.kind_of? Array
            cred_details.each do |detail|
              unless detail.kind_of? Metasploit::Framework::LoginScanner::Credential
                errors.add(:cred_details, "has invalid element #{detail.inspect}")
                next
              end
              unless detail.valid?
                errors.add(:cred_details, "has invalid element #{detail.inspect}")
              end
            end
          else
            errors.add(:cred_details, "must be an array")
          end
        end



      end

    end
  end
end
