# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Pkinit
          class AttributeTypeAndValue < RASN1::Model
            sequence :attribute_type_and_value,
                     content: [objectid(:attribute_type),
                               any(:attribute_value)

            ]
          end
        end
      end
    end
  end
end
