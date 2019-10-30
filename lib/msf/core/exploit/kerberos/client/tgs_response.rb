# -*- coding: binary -*-
require 'rex/proto/kerberos'

module Msf
  class Exploit
    class Remote
      module Kerberos
        module Client
          module TgsResponse

            # Extracts the Kerberos credentials, buildint a MIT Cache Credential,
            # from a Kerberos TGS response.
            #
            # @param res [Rex::Proto::Kerberos::Model::KdcResponse]
            # @param key [String]
            # @return [Rex::Proto::Kerberos::CredentialCache::Cache]
            # @see Rex::Proto::Kerberos::Model::EncKdcResponse
            # @see Rex::Proto::Kerberos::Model::EncKdcResponse.decode
            # @see Msf::Kerberos::Client::CacheCredential
            # @see Rex::Proto::Kerberos::CredentialCache::Cache
            def extract_kerb_creds(res, key)
              decrypt_res = res.enc_part.decrypt(key, Rex::Proto::Kerberos::Crypto::ENC_TGS_RESPONSE)
              enc_res = Rex::Proto::Kerberos::Model::EncKdcResponse.decode(decrypt_res)

              client = create_cache_principal(
                  name_type: res.cname.name_type,
                  realm: res.crealm,
                  components: res.cname.name_string
              )

              server = create_cache_principal(
                  name_type: enc_res.sname.name_type,
                  realm: enc_res.srealm,
                  components: enc_res.sname.name_string
              )

              key = create_cache_key_block(
                  key_type: enc_res.key.type,
                  key_value: enc_res.key.value
              )

              times = create_cache_times(
                  auth_time: enc_res.auth_time,
                  start_time: enc_res.start_time,
                  end_time: enc_res.end_time,
                  renew_till: enc_res.renew_till
              )

              credential = create_cache_credential(
                  client: client,
                  server: server,
                  key: key,
                  time: times,
                  ticket: res.ticket.encode,
                  flags: enc_res.flags
              )

              cache_principal = create_cache_principal(
                  name_type: res.cname.name_type, # NT_PRINCIPAL
                  #realm: realm,# opts[:realm],
                  realm: res.crealm,
                  #components: user # [opts[:cname]]
                  components: res.cname.name_string
              )

              cache = create_cache(
                  primary_principal: cache_principal,
                  credentials: [credential]
              )

              cache
            end
          end
        end
      end
    end
  end
end
