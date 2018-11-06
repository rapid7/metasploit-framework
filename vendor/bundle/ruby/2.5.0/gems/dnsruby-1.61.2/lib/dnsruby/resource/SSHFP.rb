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
    class SSHFP < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::SSHFP #:nodoc: all

      attr_accessor :alg
      attr_accessor :fptype
      attr_accessor :fp

      class Algorithms < CodeMapper
        RSA = 1
        DSS = 2
        update()
      end

      class FpTypes < CodeMapper
        SHA1 = 1
        update()
      end

      def from_data(data) #:nodoc: all
        alg, fptype, @fp = data
        @alg = Algorithms.new(alg)
        @fptype = FpTypes.new(fptype)
      end

      def from_hash(hash)
        if hash[:alg]
          @alg = Algorithms.new(hash[:alg])
        end
        if hash[:fptype]
          @fptype = FpTypes.new(hash[:fptype])
        end
        if hash[:fp]
          @fp = hash[:fp]
        end
      end

      def from_string(input)
        if (input.length > 0)
          names = input.split(" ")
          begin
            @alg = Algorithms.new(names[0].to_i)
          rescue ArgumentError
            @alg = Algorithms.new(names[0])
          end
          begin
            @fptype = FpTypes.new(names[1].to_i)
          rescue ArgumentError
            @fptype = FpTypes.new(names[1])
          end
          remaining = ""
          for i in 2..(names.length + 1)
            remaining += names[i].to_s
          end
          @fp = [remaining].pack("H*")
        end
      end

      def rdata_to_string
        ret = "#{@alg.code} #{@fptype.code} "
        ret += @fp.unpack("H*")[0]
        return ret
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_pack("c", @alg.code)
        msg.put_pack("c", @fptype.code)
        msg.put_bytes(@fp)
      end

      def self.decode_rdata(msg) #:nodoc: all
        alg, fptype = msg.get_unpack("cc")
        fp = msg.get_bytes
        return self.new([alg, fptype, fp])
      end
    end
  end
end
