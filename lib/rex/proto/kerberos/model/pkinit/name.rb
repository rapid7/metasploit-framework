# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Pkinit
          class Name
            attr_accessor :value

            def parse!(str, ber: false)
              self.value = OpenSSL::X509::Name.new(str)
              to_der.length
            end

            def to_der
              self.value.to_der
            end
          end
        end
      end
    end
  end
end
