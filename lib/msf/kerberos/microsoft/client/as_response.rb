# -*- coding: binary -*-
require 'rex/proto/kerberos'

module Msf
  module Kerberos
    module Microsoft
      module Client
        module AsResponse

          # @param res [Rex::Proto::Kerberos::Model::KdcResponse]
          # @param key [String]
          # @return [Rex::Proto::Kerberos::Model::EncryptionKey]
          def extract_session_key(res, key)
            decrypt_res = res.enc_part.decrypt(key, 8)
            enc_kdc_res = Rex::Proto::Kerberos::Model::EncKdcResponse.decode(decrypt_res)

            enc_kdc_res.key
          end

          # @param res [Rex::Proto::Kerberos::Model::KdcResponse]
          # @param key [String]
          # @return [Fixnum]
          def extract_logon_time(res, key)
            decrypt_res = res.enc_part.decrypt(key, 8)
            enc_kdc_res = Rex::Proto::Kerberos::Model::EncKdcResponse.decode(decrypt_res)

            auth_time = enc_kdc_res.auth_time

            auth_time.to_i
          end
        end
      end
    end
  end
end
