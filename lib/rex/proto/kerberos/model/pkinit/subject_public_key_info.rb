# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Pkinit
          class SubjectPublicKeyInfo < RASN1::Model
            sequence :subject_public_key_info,
                    explicit: 1, constructed: true, optional: true,
                     content: [model(:algorithm, AlgorithmIdentifier),
                               bit_string(:subject_public_key)
            ]
          end
        end
      end
    end
  end
end
