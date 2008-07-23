##
#
# Net::DNS::RR::MX
#
#       $Id: MX.rb,v 1.8 2006/07/28 07:33:36 bluemonk Exp $     
#
##


module Net
  module DNS
    class RR
      
      #------------------------------------------------------------
      # RR type MX
      #------------------------------------------------------------
      class MX < RR
        attr_reader :preference, :exchange

        private
        
        def check_mx(str)
          if str.strip =~ /^(\d+)\s+(\S+)$/
            return $1.to_i,$2
          else
            raise RRArgumentError, "MX section not valid"
          end
        end
        
        def build_pack
          @mx_pack = [@preference].pack("n") + pack_name(@exchange)
          @rdlength = @mx_pack.size
        end

        def set_type
          @type = Net::DNS::RR::Types.new("MX")
        end

        def get_data
          @mx_pack
        end

        def get_inspect
          "#@preference #@exchange"
        end

        def subclass_new_from_hash(args)
          if args.has_key? :preference and args.has_key? :exchange
            @preference = args[0][:preference].to_i
            @exchange =  args[0][:exchange]
          else
            raise RRArgumentError, ":preference and :exchange fields are mandatory but missing"
          end
        end

        def subclass_new_from_string(str)
          @preference,@exchange = check_mx(str)
        end

        def subclass_new_from_binary(data,offset)
          @preference = data.unpack("@#{offset} n")[0]
          offset += 2
          @exchange,offset = dn_expand(data,offset)
          return offset
        end

      end # class MX
      
    end # class RR
  end # module DNS
end # module Net



