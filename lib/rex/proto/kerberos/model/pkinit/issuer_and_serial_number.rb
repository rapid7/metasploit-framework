# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Pkinit
          class IssuerAndSerialNumber < RASN1::Model
            sequence :signer_identifier,
                     content: [model(:issuer, Name),
                               integer(:serial_number)
            ]
          end
        end
      end
    end
  end
end
