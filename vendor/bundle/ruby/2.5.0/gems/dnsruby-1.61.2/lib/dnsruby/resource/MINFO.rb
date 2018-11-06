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
    # Class for DNS Mailbox Information (MINFO) resource records.
    # RFC 1035 Section 3.3.7
    class MINFO < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::MINFO #:nodoc: all

      # The RR's responsible mailbox field.  See RFC 1035.
      attr_accessor :rmailbx
      # The RR's error mailbox field.
      attr_accessor :emailbx

      def from_hash(hash) #:nodoc: all
        if (hash[:rmailbx])
          @rmailbx = Name.create(hash[:rmailbx])
        end
        if (hash[:emailbx])
          @emailbx = Name.create(hash[:emailbx])
        end
      end

      def from_data(data) #:nodoc: all
        @rmailbx, @emailbx = data
      end

      def from_string(input) #:nodoc: all
        if (input.length > 0)
          names = input.split(" ")
          @rmailbx = Name.create(names[0])
          @emailbx = Name.create(names[1])
        end
      end

      def rdata_to_string #:nodoc: all
        if (@rmailbx!=nil)
          return "#{@rmailbx.to_s(true)} #{@emailbx.to_s(true)}"
        else
          return ""
        end
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_name(@rmailbx, canonical)
        msg.put_name(@emailbx, canonical)
      end

      def self.decode_rdata(msg) #:nodoc: all
        rmailbx = msg.get_name
        emailbx = msg.get_name
        return self.new([rmailbx, emailbx])
      end
    end
  end
end