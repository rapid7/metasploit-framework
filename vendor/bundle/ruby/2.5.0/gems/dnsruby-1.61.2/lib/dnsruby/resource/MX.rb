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
    # Class for DNS Mail Exchanger (MX) resource records.
    # RFC 1035 Section 3.3.9
    class MX < RR
      ClassValue = nil #:nodoc: all
      TypeValue= Types::MX #:nodoc: all

      # The preference for this mail exchange.
      attr_accessor :preference
      # The name of this mail exchange.
      attr_accessor :exchange

      def from_hash(hash) #:nodoc: all
        @preference = hash[:preference]
        @exchange = Name.create(hash[:exchange])
      end

      def from_data(data) #:nodoc: all
        @preference, @exchange = data
      end

      def from_string(input) #:nodoc: all
        if (input.length > 0)
          names = input.split(" ")
          if(names.size != 2)
            raise DecodeError.new("MX record expects preference and domain")
          end
          @preference = names[0].to_i
          @exchange = Name.create(names[1])
        end
      end

      def rdata_to_string #:nodoc: all
        if (@preference!=nil)
          return "#{@preference} #{@exchange.to_s(true)}"
        else
          return ""
        end
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_pack('n', @preference, canonical)
        msg.put_name(@exchange, canonical)
      end

      def self.decode_rdata(msg) #:nodoc: all
        preference, = msg.get_unpack('n')
        exchange = msg.get_name
        return self.new([preference, exchange])
      end
    end
  end
end