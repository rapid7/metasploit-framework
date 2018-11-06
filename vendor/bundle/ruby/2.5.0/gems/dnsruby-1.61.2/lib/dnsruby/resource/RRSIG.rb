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
    #  (RFC4034, section 3)
    # DNSSEC uses public key cryptography to sign and authenticate DNS
    # resource record sets (RRsets).  Digital signatures are stored in
    # RRSIG resource records and are used in the DNSSEC authentication
    # process described in [RFC4035].  A validator can use these RRSIG RRs
    # to authenticate RRsets from the zone.  The RRSIG RR MUST only be used
    # to carry verification material (digital signatures) used to secure
    # DNS operations.
    # 
    # An RRSIG record contains the signature for an RRset with a particular
    # name, class, and type.  The RRSIG RR specifies a validity interval
    # for the signature and uses the Algorithm, the Signer's Name, and the
    # Key Tag to identify the DNSKEY RR containing the public key that a
    # validator can use to verify the signature.
    class RRSIG < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::RRSIG #:nodoc: all

      #  3.1.  RRSIG RDATA Wire Format
      # 
      #    The RDATA for an RRSIG RR consists of a 2 octet Type Covered field, a
      #    1 octet Algorithm field, a 1 octet Labels field, a 4 octet Original
      #    TTL field, a 4 octet Signature Expiration field, a 4 octet Signature
      #    Inception field, a 2 octet Key tag, the Signer's Name field, and the
      #    Signature field.
      # 
      #                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
      #     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #    |        Type Covered           |  Algorithm    |     Labels    |
      #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #    |                         Original TTL                          |
      #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #    |                      Signature Expiration                     |
      #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #    |                      Signature Inception                      |
      #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #    |            Key Tag            |                               /
      #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         /
      #    /                                                               /
      #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #    /                                                               /
      #    /                            Signature                          /
      #    /                                                               /
      #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

      # The type covered by this RRSIG
      attr_reader :type_covered
      # The algorithm used for this RRSIG
      # See Dnsruby::Algorithms for permitted values
      attr_reader :algorithm
      # The number of labels in the original RRSIG RR owner name
      # Can be used to determine if name was synthesised from a wildcard.
      attr_accessor :labels
      # The TTL of the covered RRSet as it appears in the authoritative zone
      attr_accessor :original_ttl
      # The signature expiration
      attr_accessor :expiration
      # The signature inception
      attr_accessor :inception
      # The key tag value of the DNSKEY RR that validates this signature
      attr_accessor :key_tag
      # identifies the owner name of the DNSKEY RR that a validator is
      # supposed to use to validate this signature
      attr_reader :signers_name

      # contains the cryptographic signature that covers
      # the RRSIG RDATA (excluding the Signature field) and the RRset
      # specified by the RRSIG owner name, RRSIG class, and RRSIG Type
      # Covered field
      attr_accessor :signature

      def init_defaults
        @algorithm=Algorithms.RSASHA1
        @type_covered = Types::A
        @original_ttl = 3600
        @inception = Time.now.to_i
        @expiration = Time.now.to_i
        @key_tag = 0
        @labels = 0
        self.signers_name="."
        @signature = "\0"
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
      end

      def type_covered=(t)
        begin
          type = Types.new(t)
          @type_covered = type
        rescue ArgumentError => e
          raise DecodeError.new(e)
        end
      end

      def signers_name=(s)
        begin
          name = Name.create(s)
          @signers_name = name
        rescue ArgumentError => e
          raise DecodeError.new(e)
        end
      end


      def from_data(data) #:nodoc: all
        type_covered, algorithm, @labels, @original_ttl, expiration, inception,
          @key_tag, signers_name, @signature = data
        @expiration = expiration
        @inception = inception
        self.type_covered=(type_covered)
        self.signers_name=(signers_name)
        self.algorithm=(algorithm)
      end

      def from_string(input)
        if (input.length > 0)
          data = input.split(" ")
          self.type_covered=(data[0])
          self.algorithm=(data[1])
          self.labels=data[2].to_i
          self.original_ttl=data[3].to_i
          self.expiration=get_time(data[4])
          #  Brackets may also be present
          index = 5
          end_index = data.length - 1
          if (data[index]=="(")
            index = 6
            end_index = data.length - 2
          end
          self.inception=get_time(data[index])
          self.key_tag=data[index+1].to_i
          self.signers_name=(data[index+2])
          #  signature can include whitespace - include all text
          #  until we come to " )" at the end, and then gsub
          #  the white space out
          buf=""
          (index+3..end_index).each {|i|
            if (comment_index = data[i].index(";"))
              buf += data[i].slice(0, comment_index)
              #  @TODO@ We lose the comments here - we should really keep them for when we write back to string format?
              break
            else
            buf += data[i]
            end
          }
          buf.gsub!(/\n/, "")
          buf.gsub!(/ /, "")
          # self.signature=Base64.decode64(buf)
          self.signature=buf.unpack("m*")[0]
        end
      end

      def RRSIG.get_time(input)
        if input.kind_of?(Integer)
          return input
        end
        #  RFC 4034, section 3.2
        # The Signature Expiration Time and Inception Time field values MUST be
        #    represented either as an unsigned decimal integer indicating seconds
        #    since 1 January 1970 00:00:00 UTC, or in the form YYYYMMDDHHmmSS in
        #    UTC, where:
        # 
        #       YYYY is the year (0001-9999, but see Section 3.1.5);
        #       MM is the month number (01-12);
        #       DD is the day of the month (01-31);
        #       HH is the hour, in 24 hour notation (00-23);
        #       mm is the minute (00-59); and
        #       SS is the second (00-59).
        # 
        #    Note that it is always possible to distinguish between these two
        #    formats because the YYYYMMDDHHmmSS format will always be exactly 14
        #    digits, while the decimal representation of a 32-bit unsigned integer
        #    can never be longer than 10 digits.
        if (input.length == 10)
          return input.to_i
        elsif (input.length == 14)
          year = input[0,4]
          mon=input[4,2]
          day=input[6,2]
          hour=input[8,2]
          min=input[10,2]
          sec=input[12,2]
          #  @TODO@ REPLACE THIS BY LOCAL CODE - Time.gm DOG SLOW!
          return Time.gm(year, mon, day, hour, min, sec).to_i
        else
          raise DecodeError.new("RRSIG : Illegal time value #{input} - see RFC 4034 section 3.2")
        end
      end

      def get_time(input)
        return RRSIG.get_time(input)
      end

      def format_time(time)
        return Time.at(time).gmtime.strftime("%Y%m%d%H%M%S")
      end

      def rdata_to_string #:nodoc: all
        if (@type_covered!=nil)
#          signature = Base64.encode64(@signature) # .gsub(/\n/, "")
          signature = [@signature].pack("m*").gsub(/\n/, "")
          #  @TODO@ Display the expiration and inception as
          return "#{@type_covered.string} #{@algorithm.string} #{@labels} #{@original_ttl} " +
            "#{format_time(@expiration)} ( #{format_time(@inception)} " +
            "#{@key_tag} #{@signers_name.to_s(true)} #{signature} )"
        else
          return ""
        end
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        #  2 octets, then 2 sets of 1 octet
        msg.put_pack('ncc', @type_covered.to_i, @algorithm.to_i, @labels)
        msg.put_pack("NNN", @original_ttl, @expiration, @inception)
        msg.put_pack("n", @key_tag)
        msg.put_name(@signers_name, canonical, false)
        msg.put_bytes(@signature)
      end

      def self.decode_rdata(msg) #:nodoc: all
        type_covered, algorithm, labels = msg.get_unpack('ncc')
        original_ttl, expiration, inception = msg.get_unpack('NNN')
        key_tag, = msg.get_unpack('n')
        signers_name = msg.get_name
        signature  = msg.get_bytes
        return self.new(
          [type_covered, algorithm, labels, original_ttl, expiration,
            inception, key_tag, signers_name, signature])
      end

      def sig_data
        # RRSIG_RDATA is the wire format of the RRSIG RDATA fields
        # with the Signer's Name field in canonical form and
        # the Signature field excluded;
        data = MessageEncoder.new { |msg|
          msg.put_pack('ncc', @type_covered.to_i, @algorithm.to_i, @labels)
          msg.put_pack("NNN", @original_ttl, @expiration, @inception)
          msg.put_pack("n", @key_tag)
          msg.put_name(@signers_name, true)
        }.to_s
        return data
      end
    end
  end
end