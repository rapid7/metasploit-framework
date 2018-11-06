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
    # The NSEC3PARAM RR contains the NSEC3 parameters (hash algorithm,
    # flags, iterations and salt) needed by authoritative servers to
    # calculate hashed owner names.  The presence of an NSEC3PARAM RR at a
    # zone apex indicates that the specified parameters may be used by
    # authoritative servers to choose an appropriate set of NSEC3 RRs for
    # negative responses.  The NSEC3PARAM RR is not used by validators or
    # resolvers.
    class NSEC3PARAM < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::NSEC3PARAM #:nodoc: all

      # The Hash Algorithm field identifies the cryptographic hash algorithm
      # used to construct the hash-value.
      attr_reader :hash_alg
      # The Flags field contains 8 one-bit flags that can be used to indicate
      # different processing.  All undefined flags must be zero.  The only
      # flag defined by the NSEC3 specification is the Opt-Out flag.
      attr_reader :flags
      # The Iterations field defines the number of additional times the hash
      # function has been performed.
      attr_accessor :iterations
      # The Salt Length field defines the length of the Salt field in octets,
      # ranging in value from 0 to 255.
      attr_reader :salt_length

      # The Salt field is appended to the original owner name before hashing
      # in order to defend against pre-calculated dictionary attacks.
      def salt
        return NSEC3.encode_salt(@salt)
      end

      def salt=(s)
        @salt = NSEC3.decode_salt(s)
        @salt_length = @salt.length
      end

      def hash_alg=(a)
        if (a.instance_of?String)
          if (a.length == 1)
            a = a.to_i
          end
        end
        begin
          alg = Nsec3HashAlgorithms.new(a)
          @hash_alg = alg
        rescue ArgumentError => e
          raise DecodeError.new(e)
        end
      end

      def types=(t)
        @types = NSEC.get_types(t)
      end

      def flags=(f)
        if (f==0 || f==1)
          @flags=f
        else
          raise DecodeError.new("Unknown NSEC3 flags field - #{f}")
        end
      end

      #       def salt_length=(l) # :nodoc: all
      #         if ((l < 0) || (l > 255))
      #           raise DecodeError.new("NSEC3 salt length must be between 0 and 255")
      #         end
      #         @salt_length = l
      #       end
      # 
      def from_data(data) #:nodoc: all
        hash_alg, flags, iterations, salt_length, salt = data
        self.hash_alg=(hash_alg)
        self.flags=(flags)
        self.iterations=(iterations)
        #         self.salt_length=(salt_length)
#        self.salt=(salt)
        @salt=salt
      end

      def from_string(input)
        if (input.length > 0)
          data = input.split(" ")
          self.hash_alg=(data[0]).to_i
          self.flags=(data[1]).to_i
          self.iterations=(data[2]).to_i
          self.salt=(data[3])
          #           self.salt_length=(data[3].length)
        end
      end

      def rdata_to_string #:nodoc: all
          s = salt()
          return "#{@hash_alg.code} #{@flags} #{@iterations} #{s}"
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
#        s = salt()
        s = @salt
        sl = s.length()
        if (s == "-")
          sl == 0
        end
        msg.put_pack("ccnc", @hash_alg.code, @flags, @iterations, sl)

        if (sl > 0)
          msg.put_bytes(s)
        end
      end

      def self.decode_rdata(msg) #:nodoc: all
        hash_alg, flags, iterations, salt_length = msg.get_unpack("ccnc")
        salt = msg.get_bytes(salt_length)
        return self.new(
          [hash_alg, flags, iterations, salt_length, salt])
      end
    end
  end
end