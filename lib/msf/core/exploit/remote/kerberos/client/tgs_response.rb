# -*- coding: binary -*-

module Msf
  class Exploit
    class Remote
      module Kerberos
        module Client
          # Methods for processing TGS responses.
          module TgsResponse

            # Extracts the Kerberos credentials, building a MIT Cache Credential,
            # from a Kerberos TGS response.
            #
            # @param res [Rex::Proto::Kerberos::Model::KdcResponse]
            # @param key [String]
            # @param msg_type [Rex::Proto::Kerberos::Crypto::KeyUsage]
            # @return [Rex::Proto::Kerberos::Model::EncKdcResponse]
            # @see Rex::Proto::Kerberos::Model::EncKdcResponse
            # @see Rex::Proto::Kerberos::Model::EncKdcResponse.decode
            # @see Rex::Proto::Kerberos::CredentialCache::Krb5Ccache
            def decrypt_kdc_tgs_rep_enc_part(res, key, msg_type:)
              decrypt_res = res.enc_part.decrypt_asn1(key, msg_type)
              Rex::Proto::Kerberos::Model::EncKdcResponse.decode(decrypt_res)
            end

            # Extracts the Kerberos credentials, building a MIT Cache Credential,
            # from a Kerberos TGS response.
            #
            # @param res [Rex::Proto::Kerberos::Model::KdcResponse]
            # @param key [String]
            # @return [Rex::Proto::Kerberos::CredentialCache::Krb5Ccache]
            # @see Rex::Proto::Kerberos::Model::EncKdcResponse
            # @see Rex::Proto::Kerberos::Model::EncKdcResponse.decode
            # @see Msf::Kerberos::Client::CacheCredential
            # @see Rex::Proto::Kerberos::CredentialCache::Cache
            def extract_kerb_creds(res, key, msg_type: Rex::Proto::Kerberos::Crypto::KeyUsage::TGS_REP_ENCPART_AUTHENTICATOR_SUB_KEY)
              enc_res = decrypt_kdc_tgs_rep_enc_part(res, key, msg_type: msg_type)

              Rex::Proto::Kerberos::CredentialCache::Krb5Ccache.from_responses(res, enc_res)
            end

            # Format from
            #   https://github.com/hashcat/hashcat/blob/6fce6fb3ff120ed16b300af97cf2144b36edcbe8/src/modules/module_18200.c#L126-L132
            # @param [Rex::Proto::Kerberos::Model::KdcResponse] tgsrep The krb5 tgsrep response
            # @param [String] user The username who requested the TGS
            # @return [String] A valid string format which can be cracked offline
            def format_tgs_rep_to_john_hash(tgsrep, user)
              realm = tgsrep.realm.sub(':','~')
              etype = Rex::Proto::Kerberos::Crypto::Encryption.from_etype(tgsrep.enc_part.etype)
              mac_size = etype.class::MAC_SIZE
              cipher = tgsrep.enc_part.cipher
              if [Rex::Proto::Kerberos::Crypto::Encryption::AES128, Rex::Proto::Kerberos::Crypto::Encryption::AES256].include?(tgsrep.enc_part.etype)
                user_part = "#{user}$#{realm}$*#{tgsrep.sname.name_string.join('/')}*"
                # Checksum is at the end
                checksum = cipher.last(mac_size)
                cipher_part = cipher.first(cipher.length - mac_size)
              else
                user_part = "*#{user}$#{realm}$#{tgsrep.sname.name_string.join('/')}*"
                # Checksum is at the start
                checksum = cipher[0..mac_size-1]
                cipher_part = cipher[mac_size..]
              end
              "$krb5tgs$#{tgsrep.enc_part.etype}$#{user_part}$#{checksum.unpack1('H*')}$#{cipher_part.unpack1('H*')}"
            end
          end
        end
      end
    end
  end
end
