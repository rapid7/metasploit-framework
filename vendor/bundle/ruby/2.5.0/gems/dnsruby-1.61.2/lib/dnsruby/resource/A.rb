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
      # Class for DNS Address (A) resource records.
      # 
      # RFC 1035 Section 3.4.1
      class A < RR
        ClassHash[[TypeValue = Types::A, ClassValue = ClassValue]] = self #:nodoc: all

        # The RR's (Resolv::IPv4) address field
        attr_accessor :address

        def from_data(data) #:nodoc: all
          @address = IPv4.create(data)
        end

        # Create the RR from a hash
        def from_hash(hash)
          @address = IPv4.create(hash[:address])
        end

        #  Create the RR from a standard string
        def from_string(input)
          @address = IPv4.create(input)
        end

        def rdata_to_string
          return @address.to_s
        end

        def encode_rdata(msg, canonical=false) #:nodoc: all
          msg.put_bytes(@address.address)
        end

        def self.decode_rdata(msg) #:nodoc: all
          return self.new(IPv4.new(msg.get_bytes(4)))
        end
      end
    end
  end
end