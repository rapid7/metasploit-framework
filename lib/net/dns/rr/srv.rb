##
#
# Net::DNS::RR::SRV
#
#       $Id$
#
##


module Net
  module DNS
    class RR
      
      #------------------------------------------------------------
      # RR type SRV
      #------------------------------------------------------------
      class SRV < RR
        
        attr_reader :priority, :weight, :port, :host
        
        private
        
        def build_pack
          str = ""
        end
        
        def set_type
          @type = Net::DNS::RR::Types.new("SRV")
        end
        
        def subclass_new_from_binary(data,offset)
          off_end = offset + @rdlength
          @priority, @weight, @port = data.unpack("@#{offset} n n n")
          offset+=6

          @host=[]
          while offset < off_end
            len = data.unpack("@#{offset} C")[0]
            offset += 1
            str = data[offset..offset+len-1]
            offset += len
            @host << str
          end
          @host=@host.join(".")
          offset
        end
      
      
      end # class SRV
    end # class RR
        
        
  end # module DNS
end # module Net



