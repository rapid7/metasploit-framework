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
    # Class for DNS Network Service Access Point (NSAP) resource records.
    # RFC 1706.
    class NSAP < RR
      ClassValue = nil #:nodoc: all
      TypeValue= Types::NSAP #:nodoc: all
      # The RR's authority and format identifier.  Dnsruby
      # currently supports only AFI 47 (GOSIP Version 2).
      attr_accessor :afi
      # The RR's initial domain identifier.
      attr_accessor :idi
      # The RR's DSP format identifier.
      attr_accessor :dfi
      # The RR's administrative authority.
      attr_accessor :aa
      # The RR's routing domain identifier.
      attr_accessor :rd
      # The RR's area identifier.
      attr_accessor :area
      # The RR's system identifier.
      attr_accessor :id
      # The RR's NSAP selector.
      attr_accessor :sel

      # The RR's reserved field.
      attr_writer :rsvd

      # The RR's initial domain part (the AFI and IDI fields).
      def idp
        ret = [@afi, @idi].join('')
        return ret
      end

      # The RR's domain specific part (the DFI, AA, Rsvd, RD, Area,
      # ID, and SEL fields).
      def dsp
        ret = [@dfi,@aa,rsvd,@rd,@area,@id,@sel].join('')
        return ret
      end

      def rsvd
        if (@rsvd==nil)
          return "0000"
        else
          return @rsvd
        end
      end

      # ------------------------------------------------------------------------------
      #  Usage:  str2bcd(STRING, NUM_BYTES)
      # 
      #  Takes a string representing a hex number of arbitrary length and
      #  returns an equivalent BCD string of NUM_BYTES length (with
      #  NUM_BYTES * 2 digits), adding leading zeros if necessary.
      # ------------------------------------------------------------------------------
      def str2bcd(s, bytes)
        retval = "";

        digits = bytes * 2;
        string = sprintf("%#{digits}s", s);
        string.tr!(" ","0");

        i=0;
        bytes.times do
          bcd = string[i*2, 2];
          retval += [bcd.to_i(16)].pack("C");
          i+=1
        end

        return retval;
      end


      def from_data(data) #:nodoc: all
        @afi, @idi, @dfi, @aa, @rsvd, @rd, @area, @id, @sel = data
      end

      def from_string(s) #:nodoc: all
        if (s)
          string = s.gsub(/\./, "");  # remove all dots.
          string.gsub!(/^0x/,"");  # remove leading 0x

          if (string =~ /^[a-zA-Z0-9]{40}$/)
           (@afi, @idi, @dfi, @aa, @rsvd, @rd, @area, @id, @sel) = string.unpack("A2A4A2A6A4A4A4A12A2")
          end
        end

      end

      def rdata_to_string #:nodoc: all
        rdatastr=""

        if (defined?@afi)
          if (@afi == "47")
            rdatastr = [idp, dsp].join('')
          else
            rdatastr = "; AFI #{@afi} not supported"
          end
        else
          rdatastr = ''
        end

        return rdatastr
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        if (defined?@afi)
          msg.put_pack("C", @afi.to_i(16))

          if (@afi == "47")
            msg.put_bytes(str2bcd(@idi,  2))
            msg.put_bytes(str2bcd(@dfi,  1))
            msg.put_bytes(str2bcd(@aa,   3))
            msg.put_bytes(str2bcd(0,               2))	# rsvd)
            msg.put_bytes(str2bcd(@rd,   2))
            msg.put_bytes(str2bcd(@area, 2))
            msg.put_bytes(str2bcd(@id,   6))
            msg.put_bytes(str2bcd(@sel,  1))
          end
          #  Checks for other versions would go here.
        end

        return rdata
      end

      def self.decode_rdata(msg) #:nodoc: all
        afi = msg.get_unpack("C")[0]
        afi = sprintf("%02x", afi)

        if (afi == "47")
          idi = msg.get_unpack("CC")
          dfi = msg.get_unpack("C")[0]
          aa = msg.get_unpack("CCC")
          rsvd = msg.get_unpack("CC")
          rd = msg.get_unpack("CC")
          area = msg.get_unpack("CC")
          id = msg.get_unpack("CCCCCC")
          sel = msg.get_unpack("C")[0]

          idi  = sprintf("%02x%02x", idi[0], idi[1])
          dfi  = sprintf("%02x", dfi)
          aa   = sprintf("%02x%02x%02x", aa[0], aa[1], aa[2])
          rsvd = sprintf("%02x%02x", rsvd[0],rsvd[1])
          rd   = sprintf("%02x%02x", rd[0],rd[1])
          area = sprintf("%02x%02x", area[0],area[1])
          id   = sprintf("%02x%02x%02x%02x%02x%02x", id[0],id[1],id[2],id[3],id[4],id[5])
          sel  = sprintf("%02x", sel)

        else
          #  What to do for unsupported versions?
        end
        return self.new([afi, idi, dfi, aa, rsvd, rd, area, id, sel])
      end
    end
  end
end