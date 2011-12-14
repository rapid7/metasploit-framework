class BitStruct
  # Class for unsigned integers in network order, 1-16 bits, or 8n bits.
  # Declared with BitStruct.unsigned.
  class UnsignedField < Field
    # Used in describe.
    def self.class_name
      @class_name ||= "unsigned"
    end
    
    def add_accessors_to(cl, attr = name) # :nodoc:
      offset_byte = offset / 8
      offset_bit = offset % 8
      
      length_bit = offset_bit + length
      length_byte = (length_bit/8.0).ceil
      last_byte = offset_byte + length_byte - 1
      
      divisor = options[:fixed] || options["fixed"]
      divisor_f = divisor && divisor.to_f
#      if divisor and not divisor.is_a? Fixnum
#        raise ArgumentError, "fixed-point divisor must be a fixnum"
#      end
      
      endian = (options[:endian] || options["endian"]).to_s
      case endian
      when "native"
        ctl = length_byte <= 2 ? "S" : "L"
      when "little"
        ctl = length_byte <= 2 ? "v" : "V"
      when "network", "big", ""
        ctl = length_byte <= 2 ? "n" : "N"
      else
        raise ArgumentError,
          "Unrecognized endian option: #{endian.inspect}"
      end
      
      data_is_big_endian =
        ([1234].pack(ctl) == [1234].pack(length_byte <= 2 ? "n" : "N"))
      
      if length_byte == 1
        rest = 8 - length_bit
        mask  = ["0"*offset_bit + "1"*length + "0"*rest].pack("B8")[0].ord
        mask2 = ["1"*offset_bit + "0"*length + "1"*rest].pack("B8")[0].ord
        
        cl.class_eval do
          if divisor
            define_method attr do ||
              ((self[offset_byte] & mask) >> rest) / divisor_f
            end

            define_method "#{attr}=" do |val|
              val = (val * divisor).round
              self[offset_byte] =
                (self[offset_byte] & mask2) | ((val<<rest) & mask)
            end

          else
            define_method attr do ||
              (self[offset_byte] & mask) >> rest
            end

            define_method "#{attr}=" do |val|
              self[offset_byte] =
                (self[offset_byte] & mask2) | ((val<<rest) & mask)
            end
          end
        end
      
      elsif offset_bit == 0 and length % 8 == 0
        field_length = length
        byte_range = offset_byte..last_byte
        
        cl.class_eval do
          case field_length
          when 8
            if divisor
              define_method attr do ||
                self[offset_byte] / divisor_f
              end

              define_method "#{attr}=" do |val|
                val = (val * divisor).round
                self[offset_byte] = val
              end
          
            else
              define_method attr do ||
                self[offset_byte]
              end

              define_method "#{attr}=" do |val|
                self[offset_byte] = val
              end
            end
        
          when 16, 32
            if divisor
              define_method attr do ||
                self[byte_range].unpack(ctl).first / divisor_f
              end

              define_method "#{attr}=" do |val|
                val = (val * divisor).round
                self[byte_range] = [val].pack(ctl)
              end
            
            else
              define_method attr do ||
                self[byte_range].unpack(ctl).first
              end

              define_method "#{attr}=" do |val|
                self[byte_range] = [val].pack(ctl)
              end
            end
          
          else
            reader_helper = proc do |substr|
              bytes = substr.unpack("C*")
              bytes.reverse! unless data_is_big_endian
              bytes.inject do |sum, byte|
                (sum << 8) + byte
              end
            end
            
            writer_helper = proc do |val|
              bytes = []
              while val > 0
                bytes.push val % 256
                val = val >> 8
              end
              if bytes.length < length_byte
                bytes.concat [0] * (length_byte - bytes.length)
              end

              bytes.reverse! if data_is_big_endian
              bytes.pack("C*")
            end
            
            if divisor
              define_method attr do ||
                reader_helper[self[byte_range]] / divisor_f
              end
              
              define_method "#{attr}=" do |val|
                self[byte_range] = writer_helper[(val * divisor).round]
              end
            
            else
              define_method attr do ||
                reader_helper[self[byte_range]]
              end
              
              define_method "#{attr}=" do |val|
                self[byte_range] = writer_helper[val]
              end
            end
          end
        end

      elsif length_byte == 2 # unaligned field that fits within two whole bytes
        byte_range = offset_byte..last_byte
        rest = 16 - length_bit
        
        mask  = ["0"*offset_bit + "1"*length + "0"*rest]
        mask = mask.pack("B16").unpack(ctl).first
        
        mask2 = ["1"*offset_bit + "0"*length + "1"*rest]
        mask2 = mask2.pack("B16").unpack(ctl).first

        cl.class_eval do
          if divisor
            define_method attr do ||
              ((self[byte_range].unpack(ctl).first & mask) >> rest) /
                 divisor_f
            end

            define_method "#{attr}=" do |val|
              val = (val * divisor).round
              x = (self[byte_range].unpack(ctl).first & mask2) |
                ((val<<rest) & mask)
              self[byte_range] = [x].pack(ctl)
            end

          else
            define_method attr do ||
              (self[byte_range].unpack(ctl).first & mask) >> rest
            end

            define_method "#{attr}=" do |val|
              x = (self[byte_range].unpack(ctl).first & mask2) |
                ((val<<rest) & mask)
              self[byte_range] = [x].pack(ctl)
            end
          end
        end
      
      elsif length_byte == 3 # unaligned field that fits within 3 whole bytes
        byte_range = offset_byte..last_byte
        rest = 32 - length_bit
        
        mask  = ["0"*offset_bit + "1"*length + "0"*rest]
        mask = mask.pack("B32").unpack(ctl).first
        
        mask2 = ["1"*offset_bit + "0"*length + "1"*rest]
        mask2 = mask2.pack("B32").unpack(ctl).first

        cl.class_eval do
          if divisor
            define_method attr do ||
              bytes = self[byte_range]
              bytes << 0
              ((bytes.unpack(ctl).first & mask) >> rest) /
                 divisor_f
            end

            define_method "#{attr}=" do |val|
              val = (val * divisor).round
              bytes = self[byte_range]
              bytes << 0
              x = (bytes.unpack(ctl).first & mask2) |
                ((val<<rest) & mask)
              self[byte_range] = [x].pack(ctl)[0..2]
            end

          else
            define_method attr do ||
              bytes = self[byte_range]
              bytes << 0
              (bytes.unpack(ctl).first & mask) >> rest
            end

            define_method "#{attr}=" do |val|
              bytes = self[byte_range]
              bytes << 0
              x = (bytes.unpack(ctl).first & mask2) |
                ((val<<rest) & mask)
              self[byte_range] = [x].pack(ctl)[0..2]
            end
          end
        end
      
      else
        raise "unsupported: #{inspect}"
      end
    end
  end
end
