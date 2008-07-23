##
#
# Net::DNS::RR::AAAA
#
# $id$
#
##

require 'ipaddr'

module Net 
  module DNS 
    
    class RR 

      #
      # RR type AAAA
      #
      class AAAA < RR
        attr_reader :address

        # Assign to the RR::AAAA object a new IPv6 address, which can be in the
        # form of a string or an IPAddr object
        #
        #   a.address = "::1"
        #   a.address = IPAddr.new("::1")
        #
        def address=(addr)
          @address = check_address addr
          build_pack
        end # address=
        
        private
        
        def check_address(addr)
          address = ""
          case addr
          when String 
            address = IPAddr.new addr
          when IPAddr
            address = addr
          else
            raise RRArgumentError, "Unknown address type: #{addr.inspect}"
          end
          raise RRArgumentError, "Must specify an IPv6 address" unless address.ipv6?
          address
        rescue ArgumentError
          raise RRArgumentError, "Invalid address #{addr.inspect}"
        end
          
        def build_pack
          @address_pack = @address.hton
          @rdlength = @address_pack.size
        end
        
        def set_type
          @type = Net::DNS::RR::Types.new("AAAA")
        end
        
        def get_data
          @address_pack
        end

        def get_inspect
          "#@address"
        end
        
        def subclass_new_from_hash(args)
          if args.has_key? :address 
            @address = check_address args[:address]
          else
            raise RRArgumentError, ":address field is mandatory but missing"
          end
        end
        
        def subclass_new_from_string(str)
          @address = check_address(str)
        end
        
        def subclass_new_from_binary(data,offset)
          arr = data.unpack("@#{offset} n8")
          @address = IPAddr.new sprintf("%x:%x:%x:%x:%x:%x:%x:%x",*arr)
          return offset + 16
        end
        
      end # class AAAA
      
    end # class RR
  end # module DNS
end # module Net


