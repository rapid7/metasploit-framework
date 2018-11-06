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
    # Class for DNS Responsible Person (RP) resource records.
    # RFC 1183 Section 2.2
    class RP < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::RP #:nodoc: all

      # Returns a domain name that specifies the mailbox for the responsible person.
      attr_reader :mailbox
      # A domain name that specifies a TXT record containing further
      # information about the responsible person.
      attr_reader :txtdomain

      def txtdomain=(s)
        @txtdomain = Name.create(s)
      end

      def mailbox=(s)
        @mailbox = Name.create(s)
      end

      def from_hash(hash)
        @mailbox = Name.create(hash[:mailbox])
        @txtdomain = Name.create(hash[:txtdomain])
      end

      def from_data(data) #:nodoc: all
        @mailbox, @txtdomain= data
      end

      def from_string(input) #:nodoc: all
        if (input.length > 0)
          names = input.split(" ")
          @mailbox = Name.create(names[0])
          @txtdomain = Name.create(names[1])
        end
      end

      def rdata_to_string #:nodoc: all
        if (@mailbox!=nil)
          return "#{@mailbox.to_s(true)} #{@txtdomain.to_s(true)}"
        else
          return ""
        end
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_name(@mailbox, canonical)
        msg.put_name(@txtdomain, canonical)
      end

      def self.decode_rdata(msg) #:nodoc: all
        mailbox = msg.get_name
        txtdomain = msg.get_name
        return self.new([mailbox, txtdomain])
      end
    end
  end
end
