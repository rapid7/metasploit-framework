module Dnsruby
  class RR
      class URI < RR
        ClassValue = nil #:nodoc: all
        TypeValue= Types::URI #:nodoc: all

        #  The NAPTR RR order field
        attr_accessor :priority

        #  The NAPTR RR order field
        attr_accessor :weight

        #  The NAPTR RR order field
        attr_accessor :target

        def from_hash(hash) #:nodoc: all
          @priority = hash[:priority]
          @weight = hash[:weight]
          @target = hash[:target]
        end

        def from_data(data) #:nodoc: all
          @priority,  @weight, @target = data
        end

        def from_string(input) #:nodoc: all
          if (input.strip.length > 0)
            values = input.split(" ")
            @priority = values [0].to_i
            @weight = values [1].to_i
            @target = values [2].gsub!("\"", "")
          end
        end

        def rdata_to_string #:nodoc: all
            "#{@priority} #{@weight} \"#{@target}\""
        end

        def encode_rdata(msg, canonical=false) #:nodoc: all
          if (@priority != nil)
            msg.put_pack('n', @priority)
            msg.put_pack('n', @weight)
            msg.put_bytes(@target)
          end
        end

        def self.decode_rdata(msg) #:nodoc: all
          priority, = msg.get_unpack('n')
          weight, = msg.get_unpack('n')
          target = msg.get_bytes
          return self.new([priority, weight, target])
        end


      end
  end
end
