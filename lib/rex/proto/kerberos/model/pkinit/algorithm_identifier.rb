# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Pkinit
          class AlgorithmIdentifier < RASN1::Model
            sequence :algorithm_identifier,
                     content: [objectid(:algorithm),
                               any(:parameters, optional: true)

            ]
          end
        end
      end
    end
  end
end
