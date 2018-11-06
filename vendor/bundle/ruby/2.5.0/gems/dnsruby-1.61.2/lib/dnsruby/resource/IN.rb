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
    ClassInsensitiveTypes = {
      Types::NS => NS,
      Types::CNAME => CNAME,
      Types::DNAME => DNAME,
      Types::URI => URI,
      Types::DS => DS,
      Types::CDS => CDS,
      Types::DNSKEY => DNSKEY,
      Types::CDNSKEY => CDNSKEY,
      Types::SOA => SOA,
      Types::PTR => PTR,
      Types::HINFO => HINFO,
      Types::MINFO => MINFO,
      Types::MX => MX,
      Types::TXT => TXT,
      Types::ISDN => ISDN,
      Types::MB => MB,
      Types::MG => MG,
      Types::MR => MR,
      Types::NAPTR => NAPTR,
      Types::NSAP => NSAP,
      Types::OPT => OPT,
      Types::RP => RP,
      Types::RT => RT,
      Types::X25 => X25,
      Types::KX => KX,
      Types::SPF => SPF,
      Types::CERT => CERT,
      Types::LOC => LOC,
      Types::TSIG => TSIG,
      Types::TKEY => TKEY,
      Types::ANY => ANY,
      Types::RRSIG => RRSIG,
      Types::NSEC => NSEC,
      Types::NSEC3 => NSEC3,
      Types::NSEC3PARAM => NSEC3PARAM,
      Types::DLV => DLV,
      Types::SSHFP => SSHFP,
      Types::IPSECKEY => IPSECKEY,
      Types::HIP => HIP,
      Types::DHCID => DHCID,
      Types::GPOS => GPOS,
      Types::NXT => NXT,
      Types::CAA => CAA,
    } #:nodoc: all

    #  module IN contains ARPA Internet specific RRs
    module IN
      ClassValue = Classes::IN

      ClassInsensitiveTypes::values::each {|s|
        c = Class.new(s)
        #           c < Record
        c.const_set(:TypeValue, s::TypeValue)
        c.const_set(:ClassValue, ClassValue)
        ClassHash[[s::TypeValue, ClassValue]] = c
        self.const_set(s.name.sub(/.*::/, ''), c)
      }

      #  RFC 1035, Section 3.4.2 (deprecated)
      class WKS < RR
        ClassHash[[TypeValue = Types::WKS, ClassValue = ClassValue]] = self  #:nodoc: all

        def initialize(address, protocol, bitmap)
          @address = IPv4.create(address)
          @protocol = protocol
          @bitmap = bitmap
        end
        attr_reader :address, :protocol, :bitmap

        def encode_rdata(msg, canonical=false) #:nodoc: all
          msg.put_bytes(@address.address)
          msg.put_pack("n", @protocol)
          msg.put_bytes(@bitmap)
        end

        def self.decode_rdata(msg) #:nodoc: all
          address = IPv4.new(msg.get_bytes(4))
          protocol, = msg.get_unpack("n")
          bitmap = msg.get_bytes
          return self.new(address, protocol, bitmap)
        end
      end

    end
  end
end
require 'dnsruby/resource/A'
require 'dnsruby/resource/AAAA'
require 'dnsruby/resource/AFSDB'
require 'dnsruby/resource/PX'
require 'dnsruby/resource/SRV'
require 'dnsruby/resource/APL'
require 'dnsruby/resource/TLSA'
