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
require 'digest/sha1'
module Base32
  module_function
  def encode32hex(str)
    str.gsub(/\G(.{5})|(.{1,4}\z)/mn) do
      full = $1; frag = $2
      n, c = (full || frag.ljust(5, "\0")).unpack('NC')
      full = ((n << 8) | c).to_s(32).rjust(8, '0')
      if frag
        full[0, (frag.length * 8 + 4).div(5)].ljust(8, '=').upcase
      else
        full.upcase
      end
    end
  end

  HEX = '[0-9a-v]'
  def decode32hex(str)
    str.gsub(/\G\s*(#{HEX}{8}|#{HEX}{7}=|#{HEX}{5}={3}|#{HEX}{4}={4}|#{HEX}{2}={6}|(\S))/imno) do
      raise 'invalid base32' if $2
      s = $1
      s.tr('=', '0').to_i(32).divmod(256).pack('NC')[0,
        (s.count('^=') * 5).div(8)]
    end
  end
end

module Dnsruby
  class RR
    # The NSEC3 Resource Record (RR) provides authenticated denial of
    # existence for DNS Resource Record Sets.
    # 
    # The NSEC3 RR lists RR types present at the original owner name of the
    # NSEC3 RR.  It includes the next hashed owner name in the hash order
    # of the zone.  The complete set of NSEC3 RRs in a zone indicates which
    # RRSets exist for the original owner name of the RR and form a chain
    # of hashed owner names in the zone.  This information is used to
    # provide authenticated denial of existence for DNS data.  To provide
    # protection against zone enumeration, the owner names used in the
    # NSEC3 RR are cryptographic hashes of the original owner name
    # prepended as a single label to the name of the zone.  The NSEC3 RR
    # indicates which hash function is used to construct the hash, which
    # salt is used, and how many iterations of the hash function are
    # performed over the original owner name.
    class NSEC3 < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::NSEC3 #:nodoc: all

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

      # The Hash Length field defines the length of the Next Hashed Owner
      # Name field, ranging in value from 1 to 255 octets.
      attr_reader :hash_length

      # The Next Hashed Owner Name field contains the next hashed owner name
      # in hash order.
      attr_accessor :next_hashed

      # The Type Bit Maps field identifies the RRset types that exist at the
      # NSEC RR's owner name
      attr_reader :types

      def check_name_in_range(_name)
        #  @TODO@ Check if the name is covered by this record
        false
      end

      def check_name_in_wildcard_range(_name)
        #  @TODO@ Check if the name is covered by this record
        false
      end

      def calculate_hash
        NSEC3.calculate_hash(@name, @iterations, @salt, @hash_alg)
      end

      def NSEC3.calculate_hash(name, iterations, salt, hash_alg)
        #  RFC5155
        # 5.  Calculation of the Hash

        #    Define H(x) to be the hash of x using the Hash Algorithm selected by
        #    the NSEC3 RR, k to be the number of Iterations, and || to indicate
        #    concatenation.  Then define:
        # 
        #       IH(salt, x, 0) = H(x || salt), and
        # 
        #       IH(salt, x, k) = H(IH(salt, x, k-1) || salt), if k > 0
        # 
        #    Then the calculated hash of an owner name is
        # 
        #       IH(salt, owner name, iterations),
        # 
        #    where the owner name is in the canonical form, defined as:
        # 
        #    The wire format of the owner name where:
        # 
        #    1.  The owner name is fully expanded (no DNS name compression) and
        #        fully qualified;
        #    2.  All uppercase US-ASCII letters are replaced by the corresponding
        #        lowercase US-ASCII letters;
        #    3.  If the owner name is a wildcard name, the owner name is in its
        #        original unexpanded form, including the '*' label (no wildcard
        #        substitution);
        # 
        #    This form is as defined in Section 6.2 of [RFC 4034].
        # 

        n = Name.create(name)
        out = n.canonical
        begin
          (iterations + 1).times { out = NSEC3.h(out + salt, hash_alg) }
          return Base32.encode32hex(out).downcase
        rescue ArgumentError
          TheLog.error("Unknown hash algorithm #{hash_alg} used for NSEC3 hash")
          return 'Unknown NSEC3 hash algorithm'
        end
      end

      def h(x) # :nodoc: all
        NSEC3.h(x, @hash_alg)
      end

      def NSEC3.h(x, hash_alg) # :nodoc: all
        if Nsec3HashAlgorithms.SHA_1 == hash_alg
          return Digest::SHA1.digest(x)
        end
        raise ArgumentError.new('Unknown hash algorithm')
      end

      def hash_alg=(a)
        if a.instance_of?(String)
          if a.length == 1
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
        @types = (t && t.length > 0) ? NSEC.get_types(t) : []
      end

      def add_type(t)
        self.types = (@types + [t])
      end

      OPT_OUT = 1
      def flags=(f)
        if f == 0 || f == OPT_OUT
          @flags = f
        else
          raise DecodeError.new("Unknown NSEC3 flags field - #{f}")
        end
      end

      # If the Opt-Out flag is set, the NSEC3 record covers zero or more
      # unsigned delegations.
      def opt_out?
        @flags == OPT_OUT
      end

      #       def salt_length=(l)
      #         if ((l < 0) || (l > 255))
      #           raise DecodeError.new('NSEC3 salt length must be between 0 and 255')
      #         end
      #         @salt_length = l
      #       end
      # 
      def hash_length=(l)
        if (l < 0) || (l > 255)
          raise DecodeError.new("NSEC3 hash length must be between 0 and 255 but was #{l}")
        end
        @hash_length = l
      end

      def from_data(data) #:nodoc: all
        hash_alg, flags, iterations, _salt_length, salt, hash_length, next_hashed, types = data
        self.hash_alg = hash_alg
        self.flags = flags
        self.iterations = iterations
#        self.salt_length=(salt_length)
#        self.salt=(salt)
        @salt = salt
        self.hash_length = hash_length
        self.next_hashed = next_hashed
        self.types = types
      end

      # The Salt field is appended to the original owner name before hashing
      # in order to defend against pre-calculated dictionary attacks.
      def salt
        return NSEC3.encode_salt(@salt)
      end

      def salt=(s)
        @salt = NSEC3.decode_salt(s)
        @salt_length = @salt.length
      end

      def NSEC3.decode_salt(input)
        input == '-' ? '' : [input].pack('H*')
      end

      def NSEC3.encode_salt(s)
        (!s || s.length == 0) ? '-' : s.unpack('H*')[0]
      end

      def decode_next_hashed(input)
        @next_hashed = NSEC3.decode_next_hashed(input)
      end

      def NSEC3.decode_next_hashed(input)
        return Base32.decode32hex(input)
      end

      def encode_next_hashed(n)
        return NSEC3.encode_next_hashed(n)
      end

      def NSEC3.encode_next_hashed(n)
        return Base32.encode32hex(n).downcase
      end

      def from_string(input)
        if input.length > 0
          data = input.split
          self.hash_alg = (data[0]).to_i
          self.flags = (data[1]).to_i
          self.iterations = (data[2]).to_i
          self.salt = (data[3])

          len = data[0].length + data[1].length + data[2].length + data[3].length + 4
          #  There may or may not be brackets around next_hashed
          if data[4] == '('
            len += data[4].length + 1
          end
          next_hashed_and_types = (input[len, input.length-len])
          data2 = next_hashed_and_types.split()


          self.next_hashed = decode_next_hashed(data2[0])
          self.hash_length = @next_hashed.length
          len2 = data2[0].length + 1
          self.types = next_hashed_and_types[len2, next_hashed_and_types.length - len2]
          #           self.types=data2[1]
          #           #          len = data[0].length + data[1].length + data[2].length + data[3].length + data[5].length + 7
          #           #          self.types=(input[len, input.length-len])
        end
      end

      def rdata_to_string #:nodoc: all
        if @next_hashed
          type_strings = []
          @types.each { |t| type_strings << t.string }
          #           salt = NSEC3.encode_salt(@salt)
          salt = salt()  # TODO: Remove this?
          next_hashed = encode_next_hashed(@next_hashed)
          types = type_strings.join(' ')
          "#{@hash_alg.code} #{@flags} #{@iterations} #{salt} ( #{next_hashed} #{types} )"
        else
          ''
        end
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
#        s = salt()
        s = @salt
        sl = s.length
        if s == '-'
          sl = 0
        end
        msg.put_pack('ccnc', @hash_alg.code, @flags, @iterations, sl)
        if sl > 0
          msg.put_bytes(s)
        end
        msg.put_pack('c', @hash_length)
        msg.put_bytes(@next_hashed)
        types = NSEC.encode_types(self)
        msg.put_bytes(types)
      end

      def self.decode_rdata(msg) #:nodoc: all
        hash_alg, flags, iterations, salt_length = msg.get_unpack('ccnc')
        #  Salt may be omitted
        salt = []
        if salt_length > 0
          salt = msg.get_bytes(salt_length)
        end
        hash_length, = msg.get_unpack('c')
        next_hashed = msg.get_bytes(hash_length)
        types = NSEC.decode_types(msg.get_bytes)
        return self.new(
          [hash_alg, flags, iterations, salt_length, salt, hash_length, next_hashed, types])
      end
    end
  end
end
