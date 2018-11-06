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
    # Class to store generic RRs (RFC 3597)
    class Generic < RR # RFC 3597
      # data for the generic resource record
      attr_reader :data

      def from_data(data) #:nodoc: all
        @data = data[0]
      end

      def rdata_to_string #:nodoc: all
        if (@data!=nil)
          return  "\\# " +  @data.length.to_s +  " " + @data.unpack("H*")[0]
        end
        return "#NO DATA"
      end

      def from_string(data) #:nodoc: all
        @data = data
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_bytes(data)
      end

      def self.decode_rdata(msg) #:nodoc: all
        return self.new(msg.get_bytes)
      end

      def self.create(type_value, class_value) #:nodoc:
        c = Class.new(Generic)
        #           c.type = type_value
        #           c.klass = class_value
        c.const_set(:TypeValue, type_value)
        c.const_set(:ClassValue, class_value)
        Generic.const_set("Type#{type_value}_Class#{class_value}", c)
        ClassHash[[type_value, class_value]] = c
        return c
      end
    end

    # --
    #  Standard (class generic) RRs
    # ++
    # NS RR
    # Nameserver resource record
    class NS < DomainName
      ClassValue = nil #:nodoc: all
      TypeValue = Types::NS #:nodoc: all

      alias nsdname domainname
      alias nsdname= domainname=
    end

    # CNAME RR
    # The canonical name for an alias
    class CNAME < DomainName
      ClassValue = nil #:nodoc: all
      TypeValue = Types::CNAME #:nodoc: all

      alias cname domainname
      alias cname= domainname=
    end

    # DNAME RR
    class DNAME < DomainName
      ClassValue = nil #:nodoc: all
      TypeValue = Types::DNAME #:nodoc: all

      alias dname domainname
      alias dname= domainname=
    end

    # MB RR
    class MB < DomainName
      ClassValue = nil #:nodoc: all
      TypeValue = Types::MB #:nodoc: all
      alias madname domainname
      alias madname= domainname=
    end

    # MG RR
    class MG < DomainName
      ClassValue = nil #:nodoc: all
      TypeValue = Types::MG #:nodoc: all
      alias mgmname domainname
      alias mgmname= domainname=
    end

    # MR RR
    class MR < DomainName
      ClassValue = nil #:nodoc: all
      TypeValue = Types::MR #:nodoc: all
      alias newname domainname
      alias newname= domainname=
    end

    # PTR RR
    class PTR < DomainName
      ClassValue = nil #:nodoc: all
      TypeValue = Types::PTR #:nodoc: all
    end

    # ANY RR
    #  A Query type requesting any RR
    class ANY < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::ANY #:nodoc: all
      def encode_rdata(msg, canonical=false) #:nodoc: all
        return ""
      end
      def self.decode_rdata(msg) #:nodoc: all
        return self.new([])
      end
      def from_data(data)
      end
    end
  end
end
require 'dnsruby/resource/HINFO'
require 'dnsruby/resource/MINFO'
require 'dnsruby/resource/ISDN'
require 'dnsruby/resource/MX'
require 'dnsruby/resource/NAPTR'
require 'dnsruby/resource/NSAP'
require 'dnsruby/resource/PX'
require 'dnsruby/resource/RP'
require 'dnsruby/resource/RT'
require 'dnsruby/resource/SOA'
require 'dnsruby/resource/TXT'
require 'dnsruby/resource/X25'
require 'dnsruby/resource/SPF'
require 'dnsruby/resource/CERT'
require 'dnsruby/resource/LOC'
require 'dnsruby/resource/OPT'
require 'dnsruby/resource/TSIG'
require 'dnsruby/resource/TKEY'
require 'dnsruby/resource/DNSKEY'
require 'dnsruby/resource/CDNSKEY'
require 'dnsruby/resource/RRSIG'
require 'dnsruby/resource/NSEC'
require 'dnsruby/resource/DS'
require 'dnsruby/resource/CDS'
require 'dnsruby/resource/URI'
require 'dnsruby/resource/NSEC3'
require 'dnsruby/resource/NSEC3PARAM'
require 'dnsruby/resource/DLV'
require 'dnsruby/resource/SSHFP'
require 'dnsruby/resource/IPSECKEY'
require 'dnsruby/resource/HIP'
require 'dnsruby/resource/KX'
require 'dnsruby/resource/DHCID'
require 'dnsruby/resource/GPOS'
require 'dnsruby/resource/NXT'
require 'dnsruby/resource/CAA'
