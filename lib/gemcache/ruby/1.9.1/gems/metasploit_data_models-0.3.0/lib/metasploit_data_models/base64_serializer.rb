# 2012-04-23
#
# Provides ActiveRecord 3.1x-friendly serialization for descendants of
# ActiveRecord::Base. Backwards compatible with older YAML methods and
# will fall back to string decoding in the worst case
#
# usage:
# serialize :foo, MetasploitDataModels::Base64Serializer.new
#
module MetasploitDataModels
  class Base64Serializer
    def load(value)
      return {} if value.blank?
      begin
        # Load the unpacked Marshal object first
        Marshal.load(value.unpack('m').first)
      rescue
        begin
          # Support legacy YAML encoding for existing data        
          YAML.load(value)
        rescue
          # Fall back to string decoding
          value
        end
      end
    end

    def dump(value)
      # Always store data back in the Marshal format
      [ Marshal.dump(value) ].pack('m')
    end
  end
end


