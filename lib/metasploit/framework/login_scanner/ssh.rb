require 'metasploit/framework/login_scanner/invalid'

module Metasploit
  module Framework
    module LoginScanner

      class SSH
        include ActiveModel::Validations

        # @!attribute cred_details
        #   @return [Array] An array of hashes containing the cred
        attr_accessor :cred_details
        # @!attribute host
        #   @return [String] The IP address or hostname to connect to
        attr_accessor :host
        # @!attribute port
        #   @return [Fixnum] The port to connect to
        attr_accessor :port

        validates :port,
          presence: true,
          numericality: {
              only_integer:             true,
              greater_than_or_equal_to: 1,
              less_than_or_equal_to:    65535
          }

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

        def valid!
          unless valid?
            raise Metasploit::Framework::LoginScanner::Invalid.new(self)
          end
        end

        private

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
