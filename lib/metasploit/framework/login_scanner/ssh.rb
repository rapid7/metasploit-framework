module Metasploit
  module Framework
    module LoginScanner

      class SSH
        include ActiveModel::Validations

        # @!attribute cred_pairs
        #   @return [Array] The username/password pairs to use for the login attempts
        attr_accessor :cred_pairs
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

        validates :cred_pairs, presence: true

        validate :host_address_must_be_valid

        # @param attributes [Hash{Symbol => String,nil}]
        def initialize(attributes={})
          attributes.each do |attribute, value|
            public_send("#{attribute}=", value)
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


      end

    end
  end
end
