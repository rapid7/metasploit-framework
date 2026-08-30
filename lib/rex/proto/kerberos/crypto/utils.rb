module Rex
  module Proto
    module Kerberos
      module Crypto
        module Utils
          def xor_strings(s1,s2)
            l1 = s1.unpack('C*')
            l2 = s2.unpack('C*')
            result = xor_bytes(l1, l2)
            result.pack('C*')
          end

          def xor_bytes(l1,l2)
            result = []
            l1.zip(l2).each do |b1,b2|
              if b1 != nil && b2 != nil
                result.append((b1^b2))
              end
            end

            result
          end
        end
      end
    end
  end
end
