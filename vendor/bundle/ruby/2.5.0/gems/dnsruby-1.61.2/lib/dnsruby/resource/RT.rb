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
    # Class for DNS Route Through (RT) resource records.
    # RFC 1183 Section 3.3
    class RT < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::RT #:nodoc: all

      # The preference for this route.
      attr_accessor :preference

      # The domain name of the intermediate host.
      attr_accessor :intermediate

      def from_hash(hash) #:nodoc: all
        @preference = hash[:preference]
        @intermediate = Name.create(hash[:intermediate])
      end

      def from_data(data) #:nodoc: all
        @preference, @intermediate = data
      end

      def from_string(input) #:nodoc: all
        if (input.length > 0)
          names = input.split(" ")
          @preference = names[0].to_i
          @intermediate = Name.create(names[1])
        end
      end

      def rdata_to_string #:nodoc: all
        if (@preference!=nil)
          return "#{@preference} #{@intermediate.to_s(true)}"
        else
          return ""
        end
      end

      def encode_rdata(msg, canonical = false) #:nodoc: all
        msg.put_pack('n', @preference)
        msg.put_name(@intermediate, canonical)
      end

      def self.decode_rdata(msg) #:nodoc: all
        preference, = msg.get_unpack('n')
        intermediate = msg.get_name
        return self.new([preference, intermediate])
      end
    end
  end
end
