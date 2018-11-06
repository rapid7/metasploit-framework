
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
    class HIP < RR

      ClassValue = nil #:nodoc: all
      TypeValue = Types::HIP #:nodoc: all

      # An 8-bit length for the HIT field
      attr_accessor :hit_length
      # The PK algorithm used :
      #  0 - no key present
      #  1 - DSA key present
      #  2 - RSA key present
      attr_accessor :pk_algorithm
      # An 8-bit length for the Public Key field
      attr_accessor :pk_length

      # An array of Rendezvous Servers
      attr_accessor :rsvs

      def from_data(data) #:nodoc: all
        @rsvs=[]
        @hit_length = data[0]
        @pk_algorithm = data[1]
        @pk_length = data[2]
        @hit = data[3]
        @public_key = data[4]
        @rsvs = data[5]
      end

      def from_hash(hash)
        @rsvs=[]
        @hit_length = hash[:hit_length]
        @pk_algorithm = hash[:pk_algorithm]
        @pk_length = hash[:pk_length]
        @hit = hash[:hit]
        @public_key = hash[:public_key]
        if (hash[:rsvs])
          hash[:rsvs].each {|rsv|
            @rsvs.push(Name.create(rsv))
          }
        end
      end

      # HIT field - stored in binary : client methods should handle base16(hex) encoding
      def hit_string
        #  Return hex value
        [@hit.to_s].pack("H*").gsub("\n", "")
      end
      def hit_from_string(hit_text)
        #  Decode the hex value
        hit_text.gsub!(/\n/, "")
        hit_text.gsub!(/ /, "")
        return hit_text.unpack("H*")[0]
      end

      # Public Key field - presentation format is base64 - public_key methods reused from IPSECKEY
      def public_key_string
        [@public_key.to_s].pack("m*").gsub("\n", "")
      end

      def public_key_from_string(key_text)
        key_text.gsub!(/\n/, "")
        key_text.gsub!(/ /, "")
        return key_text.unpack("m*")[0]
      end

      def from_string(input)
        @rsvs=[]
        if (input.length > 0)
          split = input.split(" ")

          @pk_algorithm = split[0].to_i
          @hit = hit_from_string(split[1])
          @hit_length = @hit.length
          @public_key = public_key_from_string(split[2])
          @pk_length = @public_key.length

          #  Now load in any RSVs there may be
          count = 3
          while (split[count])
            @rsvs.push(Name.create(split[count]))
            count += 1
          end

        end
      end

      def rdata_to_string #:nodoc: all
        ret = "#{@pk_algorithm} #{hit_string} #{public_key_string}"
        @rsvs.each {|rsv|
          ret += " #{rsv.to_s(true)}"
        }
        return ret
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all\
        msg.put_pack('ccC', @hit_length, @pk_algorithm, @pk_length)
        msg.put_bytes(@hit)
        msg.put_bytes(@public_key)
        @rsvs.each {|rsv|
          #  RSVs MUST NOT be compressed
          msg.put_name(rsv, true)
        }
      end

      def self.decode_rdata(msg) #:nodoc: all
        hit_length, pk_algorithm, pk_length = msg.get_unpack('ccC')
        hit = msg.get_bytes(hit_length)
        public_key = msg.get_bytes(pk_length)
        rsvs = []
        #  Load in the RSV names, if there are any
        while (msg.has_remaining?)
          name = msg.get_name
          rsvs.push(name)
        end
        return self.new(
          [hit_length, pk_algorithm, pk_length, hit, public_key, rsvs])
      end
    end
  end
end