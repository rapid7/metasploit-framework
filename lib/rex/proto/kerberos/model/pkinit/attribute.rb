# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Pkinit
          class Attribute < RASN1::Model
            sequence :attribute,
                     content: [objectid(:attribute_type),
                               set_of(:attribute_values, RASN1::Types::Any)

            ]
          end
        end
      end
    end
  end
end
