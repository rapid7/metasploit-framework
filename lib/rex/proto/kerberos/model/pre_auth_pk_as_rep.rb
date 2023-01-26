# -*- coding: binary -*-

require 'rasn1'
module Rex
  module Proto
    module Kerberos
      module Model
        # This class is a representation of a KERB-PA-PK-AS-REP, pre authenticated data to
        # perform PKINIT
        class PreAuthPkAsRep < RASN1::Model
          sequence :pre_auth_pk_as_rep, explicit: 0, constructed: true,
                   content: [octet_string(:dh_rep_info, implicit: 0, constructed: false),
                             octet_string(:server_dh_nonce, explicit: 1, constructed: true, optional: true)
          ]

          def dh_rep_info
            Rex::Proto::Kerberos::Model::Pkinit::ContentInfo.parse(self[:dh_rep_info].value)
          end

          def self.decode(data)
            self.parse(data)
          end
        end
      end
    end
  end
end
