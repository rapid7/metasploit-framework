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

        validates :port, numericality: {
            only_integer:             true,
            greater_than_or_equal_to: 1,
            less_than_or_equal_to:    65535
        }

        # @param attributes [Hash{Symbol => String,nil}]
        def initialize(attributes={})
          attributes.each do |attribute, value|
            public_send("#{attribute}=", value)
          end
        end


      end

    end
  end
end
