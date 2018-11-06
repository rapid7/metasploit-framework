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
    # Class for DNS Host Information (HINFO) resource records.
    class HINFO < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::HINFO #:nodoc: all

      # The CPU type for this RR.
      attr_accessor :cpu
      # The operating system type for this RR.
      attr_accessor :os

      def from_data(data) #:nodoc: all
        @cpu, @os= data
      end

      def from_string(input) #:nodoc: all
        strings = TXT.parse(input)
        cpu = ""
        os = ""
        if (strings.length == 1)
          cpu, os = input.split(" ")
        else
          cpu = strings[0]
          os = strings[1]
        end
        cpu.sub!(/^\"/, "")
        @cpu = cpu.sub(/\"$/, "")
        os.sub!(/^\"/, "")
        @os = os.sub(/\"$/, "")
      end

      def rdata_to_string #:nodoc: all
        if (defined?@cpu)
          temp = []
          [@cpu, @os].each {|str|
            output = TXT.display(str)
            temp.push("\"#{output}\"")
          }
          return temp.join(' ')
        end
        return ''
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_string(@cpu)
        msg.put_string(@os)
      end

      def self.decode_rdata(msg) #:nodoc: all
        cpu = msg.get_string
        os = msg.get_string
        return self.new([cpu, os])
      end
    end
  end
end