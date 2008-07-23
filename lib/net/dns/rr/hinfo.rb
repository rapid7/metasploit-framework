##
#
# Net::DNS::RR::HINFO
#
# $Id: HINFO.rb,v 1.4 2006/07/28 07:33:36 bluemonk Exp $
#
##

module Net
  module DNS
    class RR
      
      #------------------------------------------------------------
      # RR type HINFO
      #------------------------------------------------------------
      class HINFO < RR
        attr_reader :cpu, :os

        private
        
        def check_hinfo(str)
          if str.strip =~ /^["'](.*?)["']\s+["'](.*?)["']$/
            return $1,$2
          else
            raise RRArgumentError, "HINFO section not valid: #{str.inspect}"
          end
        end
        
        def build_pack
          @hinfo_pack = [@cpu.size].pack("C") + @cpu
          @hinfo_pack += [@os.size].pack("C") + @os
          @rdlength = @hinfo_pack.size
        end

        def set_type
          @type = Net::DNS::RR::Types.new("HINFO")
        end

        def get_data
          @hinfo_pack
        end

        def get_inspect
          "#@cpu #@os"
        end

        def subclass_new_from_hash(args)
          if args.has_key? :cpu and args.has_key? :os
            @cpu = args[:cpu]
            @os =  args[:os]
          else
            raise RRArgumentError, ":cpu and :os fields are mandatory but missing"
          end
        end

        def subclass_new_from_string(str)
          @cpu,@os = check_hinfo(str)
        end

        def subclass_new_from_binary(data,offset)
          len = data.unpack("@#{offset} C")[0]
          @cpu = data[offset+1..offset+1+len]
          offset += len+1
          len = @data.unpack("@#{offset} C")[0]
          @os = data[offset+1..offset+1+len]
          return offset += len+1
        end
        
      end # class HINFO
      
    end # class RR
  end # module DNS
end # module Net

