# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Pkinit
          class CertificateChoices < RASN1::Model
            choice :choice,
                     content: [model(:certificate, Certificate),
                               # Lots of other options; not implemented
            ]
          end
        end
      end
    end
  end
end
