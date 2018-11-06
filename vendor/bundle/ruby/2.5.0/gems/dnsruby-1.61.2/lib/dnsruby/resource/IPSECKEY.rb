# --
# Copyright 2009 Nominet UK
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
    class IPSECKEY < RR

      ClassValue = nil #:nodoc: all
      TypeValue = Types::IPSECKEY #:nodoc: all

      # An 8-bit precedence for this field. Lower values are preferred.
      attr_accessor :precedence
      # Specifies the type of gateway :
      #  0 - no gateway present
      #  1 - 4 byte IPv4 address present
      #  2 - 16 byte IPv6 address present
      #  3 - wire-encoded domain name present
      attr_accessor :gateway_type
      # The algorithm used by this key :
      #  0 - no key present
      #  1 - DSA key present
      #  2 - RSA key present
      attr_accessor :algorithm
      # The gateway. May either be a 32-bit network order IPv4 address, or a
      # 128-bit IPv6 address, or a domain name, or may not be present.
      attr_accessor :gateway

      def from_data(data) #:nodoc: all
        @precedence = data[0]
        @gateway_type = data[1]
        @algorithm = data[2]
        @public_key = nil
        @gateway = load_gateway_from_string(@gateway_type, data[3])
        if (@gateway)
          @public_key = data[4]
        else
          @public_key = data[3]
        end
      end

      def from_hash(hash)
        @precedence = hash[:precedence]
        @gateway_type = hash[:gateway_type]
        @algorithm = hash[:algorithm]
        @gateway = load_gateway_from_string(@gateway_type, hash[:gateway])
        @public_key = hash[:public_key]
      end

      def load_gateway_from_string(gateway_type, s)
        gateway = nil
        if (gateway_type == 0)
          gateway = nil
        elsif (gateway_type == 1)
          #  Load IPv4 gateway
          gateway = IPv4.create(s)
        elsif (gateway_type == 2)
          #  Load IPv6 gateway
          gateway = IPv6.create(s)
        else
          #  Load gateway domain name
          gateway = Name.create(s)
        end
        return gateway
      end

      def public_key_string
        [@public_key.to_s].pack("m*").gsub("\n", "")
      end

      def public_key_from_string(key_text)
        key_text.gsub!(/\n/, "")
        key_text.gsub!(/ /, "")
        return key_text.unpack("m*")[0]
      end

      def from_string(input)
        if (input.length > 0)
          split = input.split(" ")

          @precedence = split[0].to_i
          @gateway_type = split[1].to_i
          @algorithm = split[2].to_i

          @gateway = load_gateway_from_string(@gateway_type, split[3])

          @public_key = public_key_from_string(split[4])
        end
      end

      def rdata_to_string #:nodoc: all
        ret = "#{@precedence} #{@gateway_type} #{@algorithm} "
        if (@gateway_type > 0)
          ret += "#{@gateway} "
        end
        ret += "#{public_key_string()}"
        return ret
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_pack('ccc', @precedence, @gateway_type, @algorithm)
        if ([1,2].include?@gateway_type)
          msg.put_bytes(@gateway.address)
        end
        if (@gateway_type == 3)
          msg.put_name(@gateway, true) # gateway MUST NOT be compressed
        end
        msg.put_bytes(@public_key)
      end

      def self.decode_rdata(msg) #:nodoc: all
        precedence, gateway_type, algorithm = msg.get_unpack('ccc')
        gateway = nil
        if (gateway_type == 1)
          gateway = IPv4.new(msg.get_bytes(4))
        elsif (gateway_type == 2)
          gateway = IPv6.new(msg.get_bytes(16))
        elsif (gateway_type == 3)
          gateway = msg.get_name
        end
        public_key = msg.get_bytes
        if (gateway_type == 0)
          return self.new(
            [precedence, gateway_type, algorithm, public_key])
        else
          return self.new(
            [precedence, gateway_type, algorithm, gateway, public_key])
        end
      end
    end
  end
end