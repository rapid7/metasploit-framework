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
    # Class for DNS DHCP ID (DHCID) resource records.
    # RFC 4701
    class DHCID < RR
      ClassValue = nil #:nodoc: all
      TypeValue= Types::DHCID #:nodoc: all

      # The opaque rdata for DHCID
      attr_accessor :dhcid_data

      def from_hash(hash) #:nodoc: all
        @dhcid_data = hash[:dhcid_data]
      end

      def from_data(data) #:nodoc: all
        @dhcid_data,  = data
      end

      def from_string(input) #:nodoc: all
        buf = input.gsub(/\n/, "")
        buf.gsub!(/ /, "")
        @dhcid_data = buf.unpack("m*").first
      end

      def rdata_to_string #:nodoc: all
        return "#{[@dhcid_data.to_s].pack("m*").gsub("\n", "")}"
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_bytes(@dhcid_data)
      end

      def self.decode_rdata(msg) #:nodoc: all
        dhcid_data, = msg.get_bytes()
        return self.new([dhcid_data])
      end
    end
  end
end