require 'metasploit/framework/ftp/client'
require 'metasploit/framework/login_scanner'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with the Secure Shell protocol.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class FTP
        include ActiveModel::Validations
        include Metasploit::Framework::Ftp::Client

        # @!attribute connection_timeout
        #   @return [Fixnum] The timeout in seconds for a single SSH connection
        attr_accessor :connection_timeout
        # @!attribute cred_details
        #   @return [Array] An array of Credential objects
        attr_accessor :cred_details
        # @!attribute successes
        #   @return [Array] Array of of result objects that failed
        attr_accessor :failures
        # @!attribute ftp_timeout
        #   @return [Fixnum] The timeout in seconds to wait for a response to an FTP command
        attr_accessor :ftp_timeout
        # @!attribute host
        #   @return [String] The IP address or hostname to connect to
        attr_accessor :host
        # @!attribute max_send_size
        #   @return [Fixnum] The max size of the data to encapsulate in a single packet
        attr_accessor :max_send_size
        # @!attribute port
        #   @return [Fixnum] The port to connect to
        attr_accessor :port
        # @!attribute proxies
        #   @return [String] The proxy directive to use for the socket
        attr_accessor :proxies
        # @!attribute send_delay
        #   @return [Fixnum] The delay between sending packets
        attr_accessor :send_delay
        # @!attribute ssl
        #   @return [Boolean] Whether the socket should use ssl
        attr_accessor :ssl
        # @!attribute ssl_version
        #   @return [String] The version of SSL to implement
        attr_accessor :ssl_version
        # @!attribute stop_on_success
        #   @return [Boolean] Whether the scanner should stop when it has found one working Credential
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

        validates :ftp_timeout,
                  presence: true,
                  numericality: {
                      only_integer:             true,
                      greater_than_or_equal_to: 1
                  }

        validates :host, presence: true

        validates :max_send_size,
                  presence: true,
                  numericality: {
                      only_integer:             true,
                      greater_than_or_equal_to: 0
                  }

        validates :port,
                  presence: true,
                  numericality: {
                      only_integer:             true,
                      greater_than_or_equal_to: 1,
                      less_than_or_equal_to:    65535
                  }

        validates :send_delay,
                  presence: true,
                  numericality: {
                      only_integer:             true,
                      greater_than_or_equal_to: 0
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
          self.max_send_size = 0 if self.max_send_size.nil?
          self.send_delay = 0 if self.send_delay.nil?
        end

        # This method attempts a single login with a single credential against the target
        # @param credential [Credential] The credential object to attmpt to login with
        # @return [Metasploit::Framework::LoginScanner::Result] The LoginScanner Result object
        def attempt_login(credential)
          result_options = {
              private: credential.private,
              public: credential.public,
              realm: nil
          }

          begin
            success = connect_login(credential.public, credential.private)
          rescue ::EOFError,  Rex::AddressInUse, Rex::ConnectionError, Rex::ConnectionTimeout, ::Timeout::Error
            result_options[:status] = :connection_error
            success = false
          end


          if success
            result_options[:status] = :success
          elsif !(result_options.has_key? :status)
            result_options[:status] = :failed
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

        def chost
          '0.0.0.0'
        end

        def cport
          0
        end

        def rhost
          host
        end

        def rport
          port
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
