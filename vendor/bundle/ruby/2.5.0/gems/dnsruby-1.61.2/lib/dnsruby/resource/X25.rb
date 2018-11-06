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
    # Class for DNS X25 resource records.
    # RFC 1183 Section 3.1
    class X25 < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::X25 #:nodoc: all

      # The PSDN address
      attr_accessor :address

      def from_data(data)
        @address = data
      end

      def from_string(input)
        address = input
        address.sub!(/^\"/, "")
        @address = address.sub(/\"$/, "")
      end

      def rdata_to_string
        if (@address!=nil)
          return @address
        else
          return ""
        end
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_string(@address)
      end

      def self.decode_rdata(msg) #:nodoc: all
        address = msg.get_string
        return self.new(*address)
      end
    end
  end
end