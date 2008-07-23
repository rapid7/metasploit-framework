##
#
# Net::DNS::RR::CNAME
#
#       $Id: CNAME.rb,v 1.7 2006/07/28 07:33:36 bluemonk Exp $  
#
##

module Net
  module DNS

    class RR
      
      #------------------------------------------------------------
      # RR type CNAME
      #------------------------------------------------------------
      class CNAME < RR
        attr_reader :cname

        private
        
        def check_name(name)
          unless name =~ /(\w\.?)+\s*$/ and name =~ /[a-zA-Z]/
            raise RRArgumentError, "Canonical Name not valid: #{name}"
          end
          name
        end

        def build_pack
          @cname_pack = pack_name(@cname)
          @rdlength = @cname_pack.size
        end

        def set_type
          @type = Net::DNS::RR::Types.new("CNAME")
        end

        def get_data
          @cname_pack
        end

        def get_inspect
          "#@cname"
        end

        def subclass_new_from_hash(args)
          if args.has_key? :cname
            @cname = check_name args[:cname]
          else
            raise RRArgumentError, ":cname field is mandatory but missing"
          end
        end

        def subclass_new_from_string(str)
          @cname = check_name(str)
        end

        def subclass_new_from_binary(data,offset)
          @cname,offset = dn_expand(data,offset)
          return offset
        end
        
      end # class CNAME
       
    end # class RR
  end # module DNS
end # module Net


