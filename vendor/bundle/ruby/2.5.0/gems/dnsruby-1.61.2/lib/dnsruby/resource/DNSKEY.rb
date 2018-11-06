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
# See the License f181or the specific language governing permissions and
# limitations under the License.
# ++
module Dnsruby
  class RR
    # RFC4034, section 2
    # DNSSEC uses public key cryptography to sign and authenticate DNS
    # resource record sets (RRsets).  The public keys are stored in DNSKEY
    # resource records and are used in the DNSSEC authentication process
    # described in [RFC4035]: A zone signs its authoritative RRsets by
    # using a private key and stores the corresponding public key in a
    # DNSKEY RR.  A resolver can then use the public key to validate
    # signatures covering the RRsets in the zone, and thus to authenticate
    # them.
    class DNSKEY < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::DNSKEY #:nodoc: all

      # Key is revoked
      REVOKED_KEY = 0x80

      # Key is a zone key
      ZONE_KEY = 0x100

      # Key is a secure entry point key
      SEP_KEY = 0x1

      # The flags for the DNSKEY RR
      attr_reader :flags
      # The protocol for this DNSKEY RR.
      # MUST be 3.
      attr_reader :protocol
      # The algorithm used for this key
      # See Dnsruby::Algorithms for permitted values
      attr_reader :algorithm
      # The public key
      attr_reader :key
      # The length (in bits) of the key - NOT key.length
      attr_reader :key_length

      def init_defaults
        @make_new_key_tag = false
        self.protocol=3
        self.flags=ZONE_KEY
        @algorithm=Algorithms.RSASHA1
        @public_key = nil
        @key_tag = nil
        @make_new_key_tag = true
      end

      def protocol=(p)
        if (p!=3)
          raise DecodeError.new("DNSKEY protocol field set to #{p}, contrary to RFC4034 section 2.1.2")
        else @protocol = p
        end
        get_new_key_tag
      end

      def algorithm=(a)
        if (a.instance_of?String)
          if (a.to_i > 0)
            a = a.to_i
          end
        end
        begin
          alg = Algorithms.new(a)
          @algorithm = alg
        rescue ArgumentError => e
          raise DecodeError.new(e)
        end
        get_new_key_tag
      end

      def revoked=(on)
        if (on)
          @flags |= REVOKED_KEY
        else
          @flags &= (~REVOKED_KEY)
        end
        get_new_key_tag
      end

      def revoked?
        return ((@flags & REVOKED_KEY) > 0)
      end

      def zone_key=(on)
        if (on)
          @flags |= ZONE_KEY
        else
          @flags &= (~ZONE_KEY)
        end
        get_new_key_tag
      end

      def zone_key?
        return ((@flags & ZONE_KEY) > 0)
      end

      def sep_key=(on)
        if (on)
          @flags |= SEP_KEY
        else
          @flags &= (~SEP_KEY)
        end
        get_new_key_tag
      end

      def sep_key?
        return ((@flags & SEP_KEY) > 0)
      end

      def flags=(f)
        #  Only three values allowed -
        #  Zone Key flag (bit 7)
        #  Secure Entry Point flag (bit 15)
        #  Revoked bit (bit 8) - RFC 5011
        if ((f & ~ZONE_KEY & ~SEP_KEY & ~REVOKED_KEY) > 0)
          TheLog.info("DNSKEY: Only zone key, secure entry point and revoked flags allowed for DNSKEY" +
              " (RFC4034 section 2.1.1) : #{f} entered as input")
        end

        @flags = f
        get_new_key_tag
      end

      #       def bad_flags?
      #         if ((@flags & ~ZONE_KEY & ~SEP_KEY) > 0)
      #           return true
      #         end
      #         return false
      #       end
      # 
      def from_data(data) #:nodoc: all
        flags, protocol, algorithm, @key = data
        @make_new_key_tag = false
        self.flags=(flags)
        self.protocol=(protocol)
        self.algorithm=(algorithm)
        @make_new_key_tag = true
        get_new_key_tag
      end

      def from_hash(hash) #:nodoc: all
        @make_new_key_tag = false
        hash.keys.each do |param|
          send(param.to_s+"=", hash[param])
        end
        @make_new_key_tag = true
        get_new_key_tag
      end

      def from_string(input)
        if (input.length > 0)
          @make_new_key_tag = false
          data = input.split(" ")
          self.flags=(data[0].to_i)
          self.protocol=(data[1].to_i)
          self.algorithm=(data[2])
          #  key can include whitespace - include all text
          #  until we come to " )" at the end, and then gsub
          #  the white space out
          #  Also, brackets may or may not be present
          #  Not to mention comments! ";"
          buf = ""
          index = 3
          end_index = data.length - 1
          if (data[index]=="(")
            end_index = data.length - 2
            index = 4
          end
          (index..end_index).each {|i|
            if (comment_index = data[i].index(";"))
              buf += data[i].slice(0, comment_index)
              #  @TODO@ We lose the comments here - we should really keep them for when we write back to string format?
              break
            else
              buf += data[i]
            end
          }
          self.key=(buf)
          @make_new_key_tag = true
          get_new_key_tag
        end
      end

      def rdata_to_string #:nodoc: all
        if (@flags!=nil)
          #           return "#{@flags} #{@protocol} #{@algorithm.string} ( #{Base64.encode64(@key.to_s)} )"
          return "#{@flags} #{@protocol} #{@algorithm.string} ( #{[@key.to_s].pack("m*").gsub("\n", "")} ) ; key_tag=#{key_tag}"
        else
          return ""
        end
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        #  2 octets, then 2 sets of 1 octet
        msg.put_pack('ncc', @flags, @protocol, @algorithm.code)
        msg.put_bytes(@key)
      end

      def self.decode_rdata(msg) #:nodoc: all
        #  2 octets, then 2 sets of 1 octet
        flags, protocol, algorithm = msg.get_unpack('ncc')
        key = msg.get_bytes
        return self.new(
          [flags, protocol, algorithm, key])
      end

      #  Return the the key tag this key would have had before it was revoked
      #  If the key is not revoked, then the current key_tag will be returned
      def key_tag_pre_revoked
        if (!revoked?)
          return key_tag
        end
        new_key = clone
        new_key.revoked = false
        return new_key.key_tag
      end

      def get_new_key_tag
        if (@make_new_key_tag)
          rdata = MessageEncoder.new {|msg|
            encode_rdata(msg)
          }.to_s
          tag = generate_key_tag(rdata, @algorithm)
          @key_tag = tag
        end
      end

      #  Return the tag for this key
      def key_tag
        if (!@key_tag)
          @make_new_key_tag = true
          get_new_key_tag
        end
        return @key_tag
      end

      def generate_key_tag(rdata, algorithm)
        tag=0
        if (algorithm == Algorithms.RSAMD5)
          # The key tag for algorithm 1 (RSA/MD5) is defined differently from the
          # key tag for all other algorithms, for historical reasons.
          d1 = rdata[rdata.length - 3] & 0xFF
          d2 = rdata[rdata.length - 2] & 0xFF
          tag = (d1 << 8) + d2
        else
          tag = 0
          last = 0
          0.step(rdata.length - 1, 2) {|i|
            last = i
            d1 = rdata[i]
            d2 = rdata[i + 1] || 0 # odd number of bytes possible

            d1 = d1.getbyte(0) if d1.class == String # Ruby 1.9
            d2 = d2.getbyte(0) if d2.class == String # Ruby 1.9

            d1 = d1  & 0xFF
            d2 = d2  & 0xFF

            tag += ((d1 << 8) + d2)
          }
          last+=2
          if (last < rdata.length)
            d1 = rdata[last]

            if (d1.class == String) # Ruby 1.9
              d1 = d1.getbyte(0)
            end

            d1 = d1 & 0xFF
            tag += (d1 << 8)
          end
          tag += ((tag >> 16) & 0xFFFF)
        end
        tag=tag&0xFFFF
        return tag
      end

      def key=(key_text)
        begin
          key_text.gsub!(/\n/, "")
          key_text.gsub!(/ /, "")
          #         @key=Base64.decode64(key_text)
          @key=key_text.unpack("m*")[0]
          public_key
          get_new_key_tag
        rescue Exception
          raise ArgumentError.new("Key #{key_text} invalid")
        end
      end

      def public_key
        if (!@public_key)
          if [Algorithms.RSASHA1,
              Algorithms.RSASHA256,
              Algorithms.RSASHA512,
              Algorithms.RSASHA1_NSEC3_SHA1].include?(@algorithm)
            @public_key = rsa_key
          elsif [Algorithms.DSA,
              Algorithms.DSA_NSEC3_SHA1].include?(@algorithm)
            @public_key = dsa_key
          end
        end
        #  @TODO@ Support other key encodings!
        return @public_key
      end

      def rsa_key
        exponentLength = @key[0]
        if (exponentLength.class == String)
          exponentLength = exponentLength.getbyte(0) # Ruby 1.9
        end
        pos = 1
        if (exponentLength == 0)
          key1 = @key[1]
          if (key1.class == String) # Ruby 1.9
            key1 = key1.getbyte(0)
          end
          exponentLength = (key1<<8) + key1
          pos += 2
        end
        exponent = RR::get_num(@key[pos, exponentLength])
        pos += exponentLength

        modulus = RR::get_num(@key[pos, @key.length])
        @key_length = (@key.length - pos) * 8

        pkey = OpenSSL::PKey::RSA.new
        begin
          pkey.set_key(modulus, exponent, nil) # use set_key, present in later versions of openssl gem
        rescue NoMethodError
          pkey.e = exponent # set_key not available in earlier versions, use this approach instead
          pkey.n = modulus
        end
        return pkey
      end

      def dsa_key
        t = @key[0]
        t = t.getbyte(0) if t.class == String
        pgy_len = t * 8 + 64
        pos = 1
        q = RR::get_num(@key[pos, 20])
        pos += 20
        p = RR::get_num(@key[pos, pgy_len])
        pos += pgy_len
        g = RR::get_num(@key[pos, pgy_len])
        pos += pgy_len
        y = RR::get_num(@key[pos, pgy_len])
        pos += pgy_len
        @key_length = (pgy_len * 8)

        pkey = OpenSSL::PKey::DSA.new
        begin
          pkey.set_pgq(p,g,q)
          pkey.set_key(y, nil) # use set_pgq and set_key, present in later versions of openssl gem
        rescue NoMethodError
          pkey.p = p # set_key not available in earlier versions, use this approach instead
          pkey.q = q
          pkey.g = g
          pkey.pub_key = y
        end

        pkey
      end
    end
  end
end