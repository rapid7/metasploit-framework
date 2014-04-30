require 'metasploit/framework/login_scanner'

module Metasploit
  module Framework
    module LoginScanner

      # This module provides the base behaviour for all of
      # the LoginScanner classes. All of the LoginScanners
      # should include this module to establish base behaviour
      module Base
        extend ActiveSupport::Concern
        include ActiveModel::Validations

        included do
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
          attr_accessor :ssh_socket
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
            set_sane_defaults
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

            # Keep track of connection errors.
            # If we encounter too many, we will stop.
            consecutive_error_count = 0
            total_error_count = 0

            cred_details.each do |credential|
              result = attempt_login(credential)
              result.freeze

              yield result if block_given?

              if result.success?
                successes << result
                consecutive_error_count = 0
                break if stop_on_success
              else
                failures << result
                if result.status == :connection_error
                  consecutive_error_count += 1
                  total_error_count += 1
                  break if consecutive_error_count >= 3
                  break if total_error_count >= 10
                end
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

          # This is a placeholder method. Each LoginScanner class
          # will override this with any sane defaults specific to
          # its own behaviour.
          def set_sane_defaults
            self.connection_timeout = 30 if self.connection_timeout.nil?
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
end
