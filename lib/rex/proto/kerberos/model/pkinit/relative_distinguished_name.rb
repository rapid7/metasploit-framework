# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Pkinit
          class RelativeDistinguishedName < RASN1::Model
            set_of :relative_distinguished_name, AttributeTypeAndValue
          end
        end
      end
    end
  end
end
