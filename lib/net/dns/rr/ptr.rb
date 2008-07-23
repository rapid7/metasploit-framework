##
#
# Net::DNS::RR::PTR
#
#       $Id: PTR.rb,v 1.5 2006/07/28 07:33:36 bluemonk Exp $    
#
##

module Net
  module DNS
    class RR
      
      #------------------------------------------------------------
      # RR type PTR
      #------------------------------------------------------------
      class PTR < RR

        # Getter for PTR resource
        def ptr
          @ptrdname.to_s
        end
        alias_method :ptrdname, :ptr
        
        private
        
        def check_ptr(str)
          IPAddr.new str
        rescue
          raise RRArgumentError, "PTR section not valid"
        end
        
        def build_pack
          @ptrdname_pack = pack_name(@ptrdname)
          @rdlength = @ptrdname_pack.size
        end

        def set_type
          @type = Net::DNS::RR::Types.new("PTR")
        end

        def get_data
          @ptrdname_pack
        end

        def get_inspect
          "#@ptrdname"
        end

        def subclass_new_from_hash(args)
          if args.has_key? :ptrdname or args.has_key? :ptr
            @ptrdname = args[0][:ptrdname]
          else
            raise RRArgumentError, ":ptrdname or :ptr field is mandatory but missing"
          end
        end

        def subclass_new_from_string(str)
          @ptrdname = check_ptr(str)
        end

        def subclass_new_from_binary(data,offset)
          @ptrdname,offset = dn_expand(data,offset)
          return offset
        end

      end # class PTR
      
    end # class RR
  end # module DNS
end # module Net

