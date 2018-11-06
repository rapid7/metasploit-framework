# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++
module Dnsruby
  class RR
    # Class for CAA resource records.
    # RFC 6844
    class CAA < RR
      ClassValue = nil #:nodoc: all
      TypeValue= Types::CAA #:nodoc: all

      # The property tag for the record (issue|issuewild|iodef)
      attr_accessor :property_tag
      # The value for the property_tag
      attr_accessor :property_value
      # The value for the flag
      attr_accessor :flag

      def from_hash(hash) #:nodoc: all
        @property_tag = hash[:property_tag]
        @property_value = hash[:property_value]
        @flag = hash[:flag]
      end

      def from_data(data) #:nodoc: all
        @flag, @property_tag, @property_value = data
      end

      def flag
        @flag.to_i
      end

      def from_string(input) #:nodoc: all
        matches = (/(\d+) (issuewild|issue|iodef) "(.+)"$/).match(input)
        @flag = matches[1]
        @property_tag = matches[2]
        @property_value = matches[3]
      end

      def rdata_to_string #:nodoc: all
        "#{flag} #{@property_tag} \"#{@property_value}\""
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_pack('C', flag)
        msg.put_string(@property_tag)
        # We don't put a length byte on the final string.
        msg.put_bytes(@property_value)
      end

      def self.decode_rdata(msg) #:nodoc: all
        flag, = msg.get_unpack('C')
        property_tag = msg.get_string
        # The final string has no length byte - its length is implicit as the remainder of the packet length
        property_value = msg.get_bytes
        return self.new("#{flag} #{property_tag} \"#{property_value}\"")
      end
    end
  end
end
