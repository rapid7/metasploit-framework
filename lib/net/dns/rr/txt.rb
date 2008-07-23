##
#
# Net::DNS::RR::TXT
#
#       $Id: TXT.rb,v 1.4 2006/07/28 07:33:36 bluemonk Exp $
#
##


module Net
  module DNS
    class RR
      
      #------------------------------------------------------------
      # RR type TXT
      #------------------------------------------------------------
      class TXT < RR
        attr_reader :txt

        private
        
        def build_pack
          str = ""
          @txt.split(" ").each do |txt|
            str += [txt.length,txt].pack("C a*")
          end
          @txt_pack = str
          @rdlength = @txt_pack.size
        end
        
        def set_type
          @type = Net::DNS::RR::Types.new("TXT")
        end

        def get_data
          @txt_pack
        end

        def subclass_new_from_hash(args)
          if args.has_key? :txt
            @txt = args[:txt].strip
          else
            raise RRArgumentError, ":txt field is mandatory but missing"
          end
        end
        
        def subclass_new_from_string(str)
          @txt = str.strip
        end
        
        def subclass_new_from_binary(data,offset)
          off_end = offset + @rdlength
          @txt = ""
          while offset < off_end
            len = data.unpack("@#{offset} C")[0]
            offset += 1
            str = data[offset..offset+len-1]
            offset += len
            @txt << str << " "
          end
          return offset
        end 

      end # class TXT
      
    end # class RR
  end # module DNS
end # module Net




