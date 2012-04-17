# 2011-12-07
#
# Provides ActiveRecord 3.1x-friendly serialization for descendants of
# ActiveRecord::Base
#
# usage:
# serialize :foo, MetasploitDataModels::Base64Serializer.new
#
module MetasploitDataModels
  class Base64Serializer
    def load(value)
      return {} if value.blank?
      Marshal.load value.unpack('m').first
    end

    def dump(value)
      [ Marshal.dump(value) ].pack('m')
    end
  end
end


