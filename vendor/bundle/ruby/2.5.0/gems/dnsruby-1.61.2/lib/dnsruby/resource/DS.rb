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
require 'base64'
begin
require 'Digest/sha2'
rescue LoadError
  require 'digest/sha2'
end
module Dnsruby
  class RR
    # RFC4034, section 4
    # The DS Resource Record refers to a DNSKEY RR and is used in the DNS
    # DNSKEY authentication process.  A DS RR refers to a DNSKEY RR by
    # storing the key tag, algorithm number, and a digest of the DNSKEY RR.
    # Note that while the digest should be sufficient to identify the
    # public key, storing the key tag and key algorithm helps make the
    # identification process more efficient.  By authenticating the DS
    # record, a resolver can authenticate the DNSKEY RR to which the DS
    # record points.  The key authentication process is described in
    # [RFC4035].

    class DS < RR
      class DigestTypes < CodeMapper
        update()
        add_pair("SHA-1", 1)
        add_pair("SHA-256", 2 )
        add_pair("SHA-384", 4)
      end

      ClassValue = nil #:nodoc: all
      TypeValue = Types::DS #:nodoc: all

      # The RDATA for a DS RR consists of a 2 octet Key Tag field, a 1 octet
      # Algorithm field, a 1 octet Digest Type field, and a Digest field.
      # 
      #                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
      #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # |           Key Tag             |  Algorithm    |  Digest Type  |
      # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # /                                                               /
      # /                            Digest                             /
      # /                                                               /
      # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


      # The Key Tag field lists the key tag of the DNSKEY RR referred to by
      # the DS record, in network byte order.
      attr_accessor :key_tag
      # The algorithm used for this key
      # See Dnsruby::Algorithms for permitted values
      attr_reader :algorithm
      # The DS RR refers to a DNSKEY RR by including a digest of that DNSKEY
      # RR.  The Digest Type field identifies the algorithm used to construct
      # the digest.
      attr_reader :digest_type
      # The DS record refers to a DNSKEY RR by including a digest of that
      # DNSKEY RR.
      attr_accessor :digest
      attr_accessor :digestbin

      def digest_type=(d)
        dig = DS.get_digest_type(d)
        @digest_type = dig
      end

      def DS.get_digest_type(d)
        if (d.instance_of?String)
          if (d.length == 1)
            d = d.to_i
          end
        end
        begin
          digest = DigestTypes.new(d)
          return digest
        rescue ArgumentError => e
          raise DecodeError.new(e)
        end
      end

      def algorithm=(a)
        if (a.instance_of?String)
          if (a.length < 3)
            a = a.to_i
          end
        end
        begin
          alg = Algorithms.new(a)
          @algorithm = alg
        rescue ArgumentError => e
          raise DecodeError.new(e)
        end
      end

      #  Return the digest of the specified DNSKEY RR
      def digest_key(*args) # key, digest_type)
        digest_type = @digest_type
        key = args[0]
        if (args.length == 2)
            digest_type = args[1]
        end


        data = MessageEncoder.new {|msg|
           msg.put_name(key.name, true)
           key.encode_rdata(msg, true)
        }.to_s


        if (digest_type.code == 1)
            digestbin = OpenSSL::Digest::SHA1.digest(data)
            return digestbin
        elsif (digest_type.code == 2)
            digestbin = OpenSSL::Digest::SHA256.digest(data)
            return digestbin
        elsif (digest_type.code == 4)
            digestbin = OpenSSL::Digest::SHA384.digest(data)
            return digestbin
        end

      end

      #  Check if the key's digest is the same as that stored in the DS record
      def check_key(key)
        if ((key.key_tag == @key_tag) && (key.algorithm == @algorithm))

          digestbin = digest_key(key)
          if (@digestbin == digestbin)
            if (!key.zone_key?)
            else
              return true
            end
          else
          end
        end
        return false
      end


      def DS.from_key(key, digest_type)
# # The key must not be a NULL key.
#    if ((key.flags & 0xc000 ) == 0xc000 )
# 	puts "\nCreating a DS record for a NULL key is illegal"
#        return
#    end
# 
#    # Bit 0 must not be set.
#    if (key.flags & 0x8000)
# 	puts "\nCreating a DS record for a key with flag bit 0 set " +
# 	    "to 0 is illegal"
#          return
#    end
# 
    #  Bit 6 must be set to 0 bit 7 must be set to 1
    if (( key.flags & 0x300) != 0x100)
	puts "\nCreating a DS record for a key with flags 6 and 7 not set "+
	    "0  and 1 respectively is illegal"
         return
    end
# 
# 
#    if (key.protocol  != 3 )
# 	puts "\nCreating a DS record for a non DNSSEC (protocol=3) " +
# 	    "key is illegal"
#          return
#    end
# 
        digest_type = get_digest_type(digest_type)
        #  Create a new DS record from the specified key
        ds = RR.create(:name => key.name, :type => "DS", :ttl => key.ttl,
                      :key_tag => key.key_tag,
                     :digest_type => digest_type, :algorithm => key.algorithm)

        ds.digestbin = ds.digest_key(key, digest_type)
        ds.digest = ds.digestbin.unpack("H*")[0]
        return ds
      end

      def from_data(data) #:nodoc: all
        key_tag, algorithm, digest_type, digest = data
        self.key_tag=(key_tag)
        self.algorithm=(algorithm)
        self.digest_type=(digest_type)
        self.digestbin=(digest)
        self.digest=@digestbin.unpack("H*")[0]
      end

      def from_string(input)
        if (input.length > 0)
          data = input.split(" ")
          self.key_tag=(data[0].to_i)
          self.algorithm=(data[1])
          self.digest_type=(data[2])

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
#          self.digest=Base64.decode64(buf)
          buf.gsub!(/\n/, "")
          buf.gsub!(/ /, "")
#          self.digest=buf.unpack("m*")[0]
          self.digest=buf
          self.digestbin = [buf].pack("H*")
        end
      end

      def rdata_to_string #:nodoc: all
        if (@key_tag != nil)
#          return "#{@key_tag.to_i} #{@algorithm.string} #{@digest_type} ( #{Base64.encode64(@digest)} )"
#          return "#{@key_tag.to_i} #{@algorithm.string} #{@digest_type.code} ( #{[@digest].pack("m*").gsub("\n", "")} )"
          return "#{@key_tag.to_i} #{@algorithm.string} #{@digest_type.code} ( #{@digest.upcase} )"
        else
          return ""
        end
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_pack("ncc", @key_tag, @algorithm.code, @digest_type.code)
        msg.put_bytes(@digestbin)
      end

      def self.decode_rdata(msg) #:nodoc: all
        key_tag, algorithm, digest_type = msg.get_unpack("ncc")
        digest = msg.get_bytes
        return self.new(
          [key_tag, algorithm, digest_type, digest])
      end
    end
  end
end