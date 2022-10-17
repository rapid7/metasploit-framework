# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Pkinit
          class Name
            # Rather than specifying the entire structure of a name, we pass this off
            # to OpenSSL, effectively providing an interface between RASN and OpenSSL.
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
