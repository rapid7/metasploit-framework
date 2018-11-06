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
    # Class for EDNS pseudo resource record OPT.
    # This class is effectively internal to Dnsruby
    # See RFC 2671, RFC 2435 Section 3
    #  @TODO@ Extended labels RFC2671 section 3
    class OPT < RR #:nodoc: all
      ClassValue = nil #:nodoc: all
      TypeValue = Types::OPT #:nodoc: all
      DO_BIT = 0x8000

      ADDRESS_FAMILIES = [1, 2]
      IPV4_ADDRESS_FAMILY, IPV6_ADDRESS_FAMILY = ADDRESS_FAMILIES

      EDNS_SUBNET_OPTION = 8

      #  @TODO@ Add BADVERS to an XRCode CodeMapper object

      # Can be called with up to 3 arguments, none of which must be present
      # * OPT.new()
      # * OPT.new(size)
      # * OPT.new(size,flags)
      # * OPT.new(size,flags,options)
      def initialize(*args)
        @type = Types.new('OPT')
        @ttl = nil

        @options=nil
        if (args.length > 0)
          self.payloadsize=(args[0])
          if (args.length > 1)
            self.flags=(args[1])
            if (args.length > 2)
              self.options=(args[2])
            else
              self.options=nil
            end
          else
            self.flags=0
          end
        else
          self.payloadsize=0
        end
      end

      #  From RFC 2671 :
      #  4.3. The fixed part of an OPT RR is structured as follows:
      # 
      #      Field Name   Field Type     Description
      #      ------------------------------------------------------
      #      NAME         domain name    empty (root domain)
      #      TYPE         u_int16_t      OPT
      #      CLASS        u_int16_t      sender's UDP payload size
      #      TTL          u_int32_t      extended RCODE and flags
      #      RDLEN        u_int16_t      describes RDATA
      #      RDATA        octet stream   {attribute,value} pairs

      # 4.6. The extended RCODE and flags (which OPT stores in the RR TTL field)
      # are structured as follows:
      # 
      #                  +0 (MSB)                            +1 (LSB)
      #       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      #    0: |         EXTENDED-RCODE        |            VERSION            |
      #       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      #    2: |                               Z                               |
      #       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      # 
      #    EXTENDED-RCODE  Forms upper 8 bits of extended 12-bit RCODE.  Note
      #                    that EXTENDED-RCODE value "0" indicates that an
      #                    unextended RCODE is in use (values "0" through "15").
      # 
      #    VERSION         Indicates the implementation level of whoever sets
      #                    it.  Full conformance with this specification is
      #                    indicated by version "0."

      def flags_from_ttl
        if (@ttl)
          return [@ttl].pack("N")
        else
          return [0].pack("N")
        end
      end

      def xrcode
        return ExtendedRCode.new(flags_from_ttl[0, 1].unpack("C")[0])
      end

      def xrcode=(c)
        code = ExtendedRCode.new(c)
        @ttl = (code.code << 24) + (version() << 16) + flags()
      end

      def version
        return flags_from_ttl[1, 1].unpack("C")[0]
      end

      def version=(code)
        @ttl = (xrcode().code << 24) + (code << 16) + flags()
      end

      def flags
        return flags_from_ttl[2, 2].unpack("n")[0]
      end

      def flags=(code)
        set_flags(code)
      end

      def set_flags(code) # Should always be zero
        @ttl = (xrcode().code << 24) + (version() << 16) + code
      end

      def dnssec_ok
        return ((flags() & DO_BIT) == DO_BIT)
      end

      def dnssec_ok=(on)
        if (on)
          set_flags(flags() | DO_BIT)
        else
          set_flags(flags() & (~DO_BIT))
        end
      end

      def payloadsize
        return @klass.code
      end

      def payloadsize=(size)
        self.klass=Classes.new(size)
      end

      def options(args)
        if (args==nil)
          return @options
        elsif args.kind_of?(Integer)
          #  return list of options with that code
          ret = []
          @options.each do |option|
            if (option.code == args)
              ret.push(option)
            end
          end
          return ret
        end
      end

      def options=(options)
        @options = options
      end

      def from_data(data)
        @options = data
      end

      def from_string(input)
        raise NotImplementedError
      end

      def get_ip_addr(opt, family, source_netmask)
        pad_format_string = family == IPV4_ADDRESS_FAMILY ? 'x3C' : 'x15C'
        ip_addr = [0].pack(pad_format_string)

        num_to_copy = (source_netmask + 7) / 8
        num_to_copy.times { |index| ip_addr[index] = opt.data[index+4] }
        ip_addr
      end

      def get_client_subnet(opt)
        family = opt.data[1].unpack('C')[0]
        return "Unsupported(family=#{family})" unless ADDRESS_FAMILIES.include?(family)

        source_netmask = opt.data[2].unpack('C')[0]
        scope_netmask = opt.data[3].unpack('C')[0]

        case family
        when IPV4_ADDRESS_FAMILY
          return "#{IPAddr::ntop(get_ip_addr(opt,family,source_netmask))}/#{source_netmask}/#{scope_netmask}"
        when IPV6_ADDRESS_FAMILY
          new_ipv6 = IPAddr.new(IPAddr::ntop(get_ip_addr(opt,family,source_netmask)), Socket::AF_INET6)
          return "#{new_ipv6}/#{source_netmask}/#{scope_netmask}"
        end
      end

      def set_client_subnet(subnet)
        family = IPV4_ADDRESS_FAMILY
        scope_netmask = 0
        ip, source_netmask = subnet.split('/')
        source_netmask = source_netmask.to_i
        if subnet == "0.0.0.0/0"
          edns_client_subnet = RR::OPT::Option.new(
              EDNS_SUBNET_OPTION, [family, source_netmask, scope_netmask].pack("xcc*"))
        else
          ip_address = IPAddr.new(ip)
          family = IPV6_ADDRESS_FAMILY if ip_address.ipv6?
          num_addr_bytes = source_netmask / 8
          num_addr_bytes = num_addr_bytes + 1 if source_netmask % 8 > 0
          edns_client_subnet = RR::OPT::Option.new(EDNS_SUBNET_OPTION, [family, source_netmask, scope_netmask].pack("xcc*") +
            ip_address.hton.slice(0, num_addr_bytes))
        end
        self.options = [edns_client_subnet]
      end

      def edns_client_subnet
        return nil if @options.nil?
        subnet_option = @options.detect { |option| option.code == EDNS_SUBNET_OPTION }
        subnet_option ? get_client_subnet(subnet_option) : nil
      end

      def to_s
        ret = "OPT pseudo-record : payloadsize #{payloadsize}, xrcode #{xrcode.code}, version #{version}, flags #{flags}\n"
        if @options
          @options.each do |opt|
            if opt.code == EDNS_SUBNET_OPTION
              ret = ret + "CLIENT-SUBNET: #{get_client_subnet(opt)}"
            else
              ret = ret + " " + opt.to_s
            end
          end
        end
        ret = ret + "\n"
        return ret
      end

      def encode_rdata(msg, canonical=false)
        if (@options)
          @options.each do |opt|
            msg.put_pack('n', opt.code)
            msg.put_pack('n', opt.data.length)
            msg.put_pack('a*', opt.data)
          end
        end
      end

      def self.decode_rdata(msg)#:nodoc: all
        if (msg.has_remaining?)
          options = []
          while (msg.has_remaining?) do
            code  = msg.get_unpack('n')[0]
            len = msg.get_unpack('n')[0]
            data = msg.get_bytes(len)
            options.push(Option.new(code, data))
          end
        end
        return self.new(0, 0, options)
      end

      class Option
        attr_accessor :code, :data
        def initialize(code, data)
          @code = code
          @data = data
        end
      end
    end
  end
end
