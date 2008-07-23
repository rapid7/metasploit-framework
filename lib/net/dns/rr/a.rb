##
#
# Net::DNS::RR::A
#
# $id$
#
##

require 'ipaddr'

module Net # :nodoc:
  module DNS 
    
    class RR 

      # =Name
      #
      # Net::DNS::RR::A   DNS A resource record
      #
      # =Synopsis
      #
      # require "net/dns/rr"
      #
      # =Description
      #
      # Net::DNS::RR::A is the class to handle resource records of type A, the
      # most common in a DNS query. Its resource data is an IPv4 (i.e. 32 bit
      # long) address, hold in the instance variable +address+.  
      #    a = Net::DNS::RR::A.new("localhost.movie.edu. 360 IN A 127.0.0.1")
      #
      #    a = Net::DNS::RR::A.new(:name    => "localhost.movie.edu.",
      #                            :ttl     => 360,
      #                            :cls     => Net::DNS::IN,
      #                            :type    => Net::DNS::A,
      #                            :address => "127.0.0.1")
      #
      # When computing binary data to trasmit the RR, the RDATA section is an
      # Internet address expressed as four decimal numbers separated by dots
      # without any imbedded spaces (e.g.,"10.2.0.52" or "192.0.5.6").
      #
      class A < RR
        attr_reader :address

        # Assign to the RR::A object a new IPv4 address, which can be in the
        # form of a string or an IPAddr object
        #
        #   a.address = "192.168.0.1"
        #   a.address = IPAddr.new("10.0.0.1")
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
          when Integer # Address in numeric form
            tempAddr = [(addr>>24),(addr>>16)&0xFF,(addr>>8)&0xFF,addr&0xFF]
            tempAddr = tempAddr.collect {|x| x.to_s}.join(".")
            address = IPAddr.new tempAddr
          when IPAddr
            address = addr
          else
            raise RRArgumentError, "Unknown address type: #{addr}"
          end
          raise RRArgumentError, "Must specify an IPv4 address" unless address.ipv4?
          address
        rescue ArgumentError
          raise RRArgumentError, "Invalid address #{addr}"
        end
          
        def build_pack
          @address_pack = @address.hton
          @rdlength = @address_pack.size
        end
        
        def set_type
          @type = Net::DNS::RR::Types.new("A")
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
          elsif args.has_key? :rdata
            @address = check_address args[:rdata]
          else
            # Address field is mandatory
            raise RRArgumentError, ":address field is mandatory but missing"
          end
        end
        
        def subclass_new_from_string(str)
          @address = check_address(str)
        end
        
        def subclass_new_from_binary(data,offset)
          a,b,c,d = data.unpack("@#{offset} CCCC")
          @address = IPAddr.new "#{a}.#{b}.#{c}.#{d}"
          return offset + 4
        end
        
      end # class A
      
    end # class RR
  end # module DNS
end # module Net


