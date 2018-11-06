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
    module IN
      # Class for DNS IPv6 Address (AAAA) resource records.
      # 
      # RFC 1886 Section 2, RFC 1884 Sections 2.2 & 2.4.4
      class AAAA < RR
        ClassHash[[TypeValue = Types::AAAA, ClassValue = ClassValue]] = self #:nodoc: all

        #   The RR's (Resolv::IPv6) address field
        attr_accessor :address

        def from_data(data) #:nodoc: all
          @address = IPv6.create(data)
        end

        def from_hash(hash) #:nodoc: all
          @address = IPv6.create(hash[:address])
        end

        def from_string(input) #:nodoc: all
          @address = IPv6.create(input)
        end

        def rdata_to_string #:nodoc: all
          return @address.to_s
        end

        def encode_rdata(msg, canonical=false) #:nodoc: all
          msg.put_bytes(@address.address)
        end

        def self.decode_rdata(msg) #:nodoc: all
          return self.new(IPv6.new(msg.get_bytes(16)))
        end
      end
    end
  end
end