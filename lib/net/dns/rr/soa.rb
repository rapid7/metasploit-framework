##
#
# Net::DNS::RR::SOA
#
#       $Id: SOA.rb,v 1.4 2006/07/28 07:33:36 bluemonk Exp $    
#
##

module Net
  module DNS
    class RR

      #------------------------------------------------------------
      # RR type SOA
      #------------------------------------------------------------
      class SOA < RR
        attr_reader :mname, :rname, :serial, :refresh, :retry, :expire, :minimum
        
        private
        
        def build_pack
          @soa_pack = pack_name(@mname)
          @soa_pack += pack_name(@rname)
          @soa_pack += [@serial,@refresh,@retry,@expire,@minimum].pack("N5")
        end

        def set_type
          @type = Net::DNS::RR::Types.new("SOA")
        end

        def get_data
          @soa_pack
        end

        def get_inspect
          "#@mname #@rname #@serial #@refresh #@retry #@expire #@minimum"
        end

        def subclass_new_from_hash(args)
          if args.has_key? :rdata
            subclass_new_from_string(args[:rdata])
          else
            [:mname,:rname,:serial,:refresh,:retry,:expire,:minimum].each do |key|
              raise RRArgumentError, "Missing field :#{key}" unless args.has_key? key
            end
            @mname = args[:mname] if valid? args[:mname] 
            @rname = args[:rname] if valid? args[:rname]
            @serial = args[:serial] if number? args[:serial] 
            @refresh = args[:refresh] if number? args[:refresh] 
            @retry = args[:retry] if number? args[:retry] 
            @expire = args[:expire] if number? args[:expire] 
            @minimum = args[:minimum] if number? args[:minimum] 
          end
        end
        
        def number?(num)
          if num.kind_of? Integer and num > 0
            true
          else
            raise RRArgumentError, "Wrong format field: #{num} not a number or less than zero"
          end
        end

        def subclass_new_from_string(str)
          mname,rname,serial,refresh,ret,expire,minimum = str.strip.split(" ")
          @mname = mname if valid? mname
          @rname = rname if valid? rname
          @serial,@refresh,@retry,@expire,@minimum = [serial,refresh,ret,expire,minimum].collect do |i| 
            i.to_i if valid? i.to_i
          end
        end

        def subclass_new_from_binary(data,offset)
          @mname,offset = dn_expand(data,offset)
          @rname,offset = dn_expand(data,offset)
          @serial,@refresh,@retry,@expire,@minimum = data.unpack("@#{offset} N5")
          return offset + 5*Net::DNS::INT32SZ
        end

      end # class SOA
      
    end # class RR
  end # module DNS
end # module Net

