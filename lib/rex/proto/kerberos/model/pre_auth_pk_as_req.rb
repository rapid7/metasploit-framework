# -*- coding: binary -*-

require 'rasn1'
module Rex
  module Proto
    module Kerberos
      module Model
        # This class is a representation of a KERB-PA-PK-AS-REQ, pre authenticated data to
        # perform PKINIT
        class PreAuthPkAsReq < RASN1::Model
          sequence :pre_auth_pk_as_req,
                   content: [octet_string(:signed_auth_pack, implicit: 0, constructed: false)]

          attr_accessor :signed_auth_pack

          def parse!(der, ber: false)
            res = super(der, ber: ber)
            self.signed_auth_pack = Rex::Proto::Kerberos::Model::Pkinit::ContentInfo.parse(self[:signed_auth_pack].value)

            res
          end

          def to_der
            self[:signed_auth_pack] = self.signed_auth_pack.to_der
            super
          end

          def self.decode(str)
            self.parse(str)
          end
        end
      end
    end
  end
end
