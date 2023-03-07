# -*- coding: binary -*-

module Msf
  class Exploit
    class Remote
      module Kerberos
        module Client
          module AsResponse

            # Extracts the session key from a Kerberos AS Response
            #
            # @param res [Rex::Proto::Kerberos::Model::KdcResponse]
            # @param key [String]
            # @return [Rex::Proto::Kerberos::Model::EncKdcResponse]
            # @see Rex::Proto::Kerberos::Model::KdcResponse
            # @see Rex::Proto::Kerberos::Model::EncryptedData.decrypt
            # @see Rex::Proto::Kerberos::Model::EncKdcResponse
            # @see Rex::Proto::Kerberos::Model::EncKdcResponse.decode
            # @see Rex::Proto::Kerberos::Model::EncryptionKey
            def decrypt_kdc_as_rep_enc_part(res, key)
              decrypt_res = res.enc_part.decrypt_asn1(key, Rex::Proto::Kerberos::Crypto::KeyUsage::AS_REP_ENCPART)
              enc_res = Rex::Proto::Kerberos::Model::EncKdcResponse.decode(decrypt_res)
              enc_res
            end

            # Extracts the session key from a Kerberos AS Response
            #
            # @param res [Rex::Proto::Kerberos::Model::KdcResponse]
            # @param key [String]
            # @return [Rex::Proto::Kerberos::Model::EncryptionKey]
            # @see Rex::Proto::Kerberos::Model::KdcResponse
            # @see Rex::Proto::Kerberos::Model::EncryptedData.decrypt
            # @see Rex::Proto::Kerberos::Model::EncKdcResponse
            # @see Rex::Proto::Kerberos::Model::EncKdcResponse.decode
            # @see Rex::Proto::Kerberos::Model::EncryptionKey
            def extract_session_key(res, key)
              kdc_res = decrypt_kdc_as_rep_enc_part(res, key)
              kdc_res.key
            end

            # Extracts the logon time from a Kerberos AS Response
            #
            # @param res [Rex::Proto::Kerberos::Model::KdcResponse]
            # @param key [String]
            # @return [Time]
            # @see Rex::Proto::Kerberos::Model::KdcResponse
            # @see Rex::Proto::Kerberos::Model::EncryptedData.decrypt
            # @see Rex::Proto::Kerberos::Model::EncKdcResponse
            # @see Rex::Proto::Kerberos::Model::EncKdcResponse.decode
            def extract_logon_time(res, key)
              kdc_res = decrypt_kdc_as_rep_enc_part(res, key)
              kdc_res.auth_time
            end

            # Format from
            #   https://github.com/hashcat/hashcat/blob/6fce6fb3ff120ed16b300af97cf2144b36edcbe8/src/modules/module_18200.c#L126-L132
            # @param [Rex::Proto::Kerberos::Model::KdcResponse] asrep The krb5 asrep response
            # @return [String] A valid string format which can be cracked offline
            def format_as_rep_to_john_hash(asrep)
              "$krb5asrep$#{asrep.enc_part.etype}$#{asrep.cname.name_string.join('/')}@#{asrep.ticket.realm}:#{asrep.enc_part.cipher[0...16].unpack1('H*')}$#{asrep.enc_part.cipher[16..].unpack1('H*')}"
            end
          end
        end
      end
    end
  end
end
