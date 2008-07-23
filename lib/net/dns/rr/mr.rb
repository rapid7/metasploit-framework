##
#
# Net::DNS::RR::MR
#
#       $Id: MR.rb,v 1.4 2006/07/28 07:33:36 bluemonk Exp $
#
##

module Net
  module DNS

    class RR
      
      #------------------------------------------------------------
      # RR type MR
      #------------------------------------------------------------
      class MR < RR
        attr_reader :newname

        private
        
        def check_name(name)
          unless name =~ /(\w\.?)+\s*$/
            raise RRArgumentError, "Name not valid: #{name.inspect}"
          end
          name
        end

        def build_pack
          @newname_pack = pack_name(@newname)
          @rdlength = @newname_pack.size
        end

        def set_type
          @type = Net::DNS::RR::Types.new("MR")
        end

        def get_data
          @newname_pack
        end

        def get_inspect
          "#@newname"
        end
          
        def subclass_new_from_hash(args)
          if args.has_key? :newname
            @newname = check_name args[:newname]
          else
            raise RRArgumentError, ":newname field is mandatory but missing"
          end
        end

        def subclass_new_from_string(str)
          @newname = check_name(str)
        end

        def subclass_new_from_array(data,offset)
          @newname = dn_expand(data,offset)
          return offset
        end
        
      end # class MR

    end # class RR
  end # module DNS
end # module Net

