# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Pkinit
          class DomainParameters < RASN1::Model
            sequence :domain_parameters,
                     content: [integer(:p),
                               integer(:g),
                               integer(:q),
                               integer(:j, optional: true),
                               #model(:validationParms, ValidationParms) # Not used, so not implemented
            ]
          end
        end
      end
    end
  end
end
