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
      class PX < RR
        ClassHash[[TypeValue = Types::PX, ClassValue = Classes::IN]] = self #:nodoc: all

        # The preference given to this RR.
        attr_accessor :preference
        # The RFC822 part of the RFC1327 mapping information.
        attr_accessor :map822
        # The X.400 part of the RFC1327 mapping information.
        attr_accessor :mapx400

        def from_hash(hash) #:nodoc: all
          @preference = hash[:preference]
          @map822 = Name.create(hash[:map822])
          @mapx400 = Name.create(hash[:mapx400])
        end

        def from_data(data) #:nodoc: all
          @preference, @map822, @mapx400 = data
        end

        def from_string(input) #:nodoc: all
          if (input.length > 0)
            names = input.split(" ")
            @preference = names[0].to_i
            @map822 = Name.create(names[1])
            @mapx400 = Name.create(names[2])
          end
        end

        def rdata_to_string #:nodoc: all
          if (@preference!=nil)
            return "#{@preference} #{@map822.to_s(true)} #{@mapx400.to_s(true)}"
          else
            return ""
          end
        end

        def encode_rdata(msg, canonical=false) #:nodoc: all
          msg.put_pack('n', @preference)
          msg.put_name(@map822, canonical)
          msg.put_name(@mapx400, canonical)
        end

        def self.decode_rdata(msg) #:nodoc: all
          preference, = msg.get_unpack('n')
          map822 = msg.get_name
          mapx400 = msg.get_name
          return self.new([preference, map822, mapx400])
        end
      end
    end
  end
end