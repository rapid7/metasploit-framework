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
      # Class for DNS AFS Data Base (AFSDB) resource records.
      # 
      # RFC 1183 Section 1
      class AFSDB < RR
        ClassHash[[TypeValue = Types::AFSDB, ClassValue = ClassValue]] = self #:nodoc: all

        # The RR's subtype field.  See RFC 1183.
        attr_accessor :subtype

        # The RR's hostname field.  See RFC 1183.
        attr_accessor :hostname

        def from_hash(hash) #:nodoc: all
          @subtype = hash[:subtype]
          @hostname = Name.create(hash[:hostname])
        end

        def from_data(data) #:nodoc: all
          @subtype, @hostname = data
        end

        def from_string(input) #:nodoc: all
          if (input!=nil && (input =~ /^(\d+)\s+(\S+)$/o))
            @subtype  = $1;
            @hostname = Name.create($2)
          end
        end

        def rdata_to_string #:nodoc: all
          if defined?@subtype
            return "#{@subtype} #{@hostname.to_s(true)}"
          else
            return '';
          end
        end

        def encode_rdata(msg, canonical=false) #:nodoc: all
          msg.put_pack("n", @subtype.to_i)
          msg.put_name(@hostname, canonical)
        end

        def self.decode_rdata(msg) #:nodoc: all
          subtype,     = msg.get_unpack("n")
          hostname    = msg.get_name
          return self.new([subtype, hostname])
        end
      end
    end
  end
end
