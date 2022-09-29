# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Pkinit
          class SignedData < RASN1::Model
            sequence :signed_data,
                     explicit: 0, constructed: true,
                     content: [integer(:version),
                               set_of(:digest_algorithms, AlgorithmIdentifier),
                               model(:encap_content_info, EncapsulatedContentInfo),
                               set_of(:certificates, Certificate, implicit: 0, optional: true),
                               # CRLs - not implemented
                               set_of(:signer_infos, SignerInfo)
            ]
          end
        end
      end
    end
  end
end
