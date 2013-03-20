# Provides ActiveRecord 3.1x-friendly serialization for descendants of
# ActiveRecord::Base. Backwards compatible with older YAML methods and
# will fall back to string decoding in the worst case
#
# @example Using default default of {}
#   serialize :foo, MetasploitDataModels::Base64Serializer.new
#
# @example Overriding default to []
#   serialize :bar, MetasploitDataModels::Base64Serializer.new(:default => [])
#
module MetasploitDataModels
  class Base64Serializer
    #
    # CONSTANTS
    #

    # The default for {#default}
    DEFAULT = {}
    # Deserializers for {#load}
    # 1. Base64 decoding and then unmarshalling the value.
    # 2. Parsing the value as YAML.
    # 3. The raw value.
    LOADERS = [
        lambda { |serialized|
          marshaled = serialized.unpack('m').first
          # Load the unpacked Marshal object first
          Marshal.load(marshaled)
        },
        lambda { |serialized|
          # Support legacy YAML encoding for existing data
          YAML.load(serialized)
        },
        lambda { |serialized|
          # Fall back to string decoding
          serialized
        }
    ]

    #
    # Methods
    #

    # Creates a duplicate of default value
    #
    # @return
    def default
      @default.dup
    end

    attr_writer :default

    # Serializes the value by marshalling the value and then base64 encodes the marshaled value.
    #
    # @param value [Object] value to serialize
    # @return [String]
    def dump(value)
      # Always store data back in the Marshal format
      marshalled = Marshal.dump(value)
      base64_encoded = [ marshalled ].pack('m')

      base64_encoded
    end

    # @param attributes [Hash] attributes
    # @option attributes [Object] :default ({}) Value to use for {#default}.
    def initialize(attributes={})
      attributes.assert_valid_keys(:default)

      @default = attributes.fetch(:default, DEFAULT)
    end

    # Deserializes the value by either
    # 1. Base64 decoding and then unmarshalling the value.
    # 2. Parsing the value as YAML.
    # 3. Returns the raw value.
    #
    # @param value [String] serialized value
    # @return [Object]
    #
    # @see #default
    def load(value)
      loaded = nil

      if value.blank?
        loaded = default
      else
        LOADERS.each do |loader|
          begin
            loaded = loader.call(value)
          rescue
            next
          else
            break
          end
        end
      end

      loaded
    end
  end
end


