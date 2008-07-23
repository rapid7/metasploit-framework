##
#
# Net::DNS::RR::NULL
#
#       $Id: NULL.rb,v 1.5 2006/07/28 07:33:36 bluemonk Exp $
#
##


module Net
  module DNS
    class RR
      
      #------------------------------------------------------------
      # RR type NULL
      #------------------------------------------------------------
      class NULL < RR
        attr_reader :null

        private
        
        def build_pack
          @null_pack = @null
          @rdlength = @null_pack.size
        end

        def set_type
          @type = Net::DNS::RR::RRTypes.new("NULL")
        end

        def get_data
          @null_pack
        end

        def get_inspect
          "#@null"
        end
          
        def subclass_new_from_hash(args)
          if args.has_key? :null
            @null = args[:null]
          else
            raise RRArgumentError, ":null field is mandatory but missing"
          end
        end

        def subclass_new_from_string(str)
          @null = str.strip
        end

        def subclass_new_from_binary(data,offset)
          @null = data[offset..offset+@rdlength]
          return offset + @rdlength
        end
        
      end # class NULL
      
    end # class RR
  end # module DNS
end # module Net

