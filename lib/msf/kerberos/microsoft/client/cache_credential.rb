# -*- coding: binary -*-
require 'rex/proto/kerberos'

module Msf
  module Kerberos
    module Microsoft
      module Client
        module CacheCredential
          def create_cache(opts = {})
            version = opts[:version] || 0x0504
            headers = opts[:headers] || ["\x00\x08\xff\xff\xff\xff\x00\x00\x00\x00"]
            primary_principal = opts[:primary_principal] || create_cache_principal(opts)
            credentials = opts[:credentials] || [create_cache_credential(opts)]

            cache = Rex::Proto::Kerberos::CredentialCache::Cache.new(
              version: version,
              headers: headers,
              primary_principal: primary_principal,
              credentials: credentials
            )

            cache
          end

          def create_cache_principal(opts = {})
            name_type = opts[:name_type]
            realm = opts[:realm]
            components = opts[:components]

            principal = Rex::Proto::Kerberos::CredentialCache::Principal.new(
              name_type: name_type,
              realm: realm,
              components:components
            )

            principal
          end

          def create_cache_key_block(opts = {})
            key_type = opts[:key_type]
            e_type = opts[:e_type] || 0
            key_value = opts[:key_value]

            key_block = Rex::Proto::Kerberos::CredentialCache::KeyBlock.new(
              key_type: key_type,
              e_type: e_type,
              key_value: key_value
            )

            key_block
          end

          def create_cache_times(opts = {})
            auth_time = opts[:auth_time]
            start_time = opts[:start_time] || 0
            end_time = opts[:end_time] || 0
            renew_till = opts[:renew_till] || 0

            time = Rex::Proto::Kerberos::CredentialCache::Time.new(
              auth_time: auth_time.to_i,
              start_time: start_time.to_i,
              end_time: end_time.to_i,
              renew_till: renew_till.to_i
            )

            time
          end

          def create_cache_credential(opts = {})
            client = opts[:client]
            server = opts[:server]
            key = opts[:key]
            time = opts[:time]
            is_skey = opts[:is_skey] || 0
            tkt_flags = opts[:flags]
            addrs = opts[:addrs] || []
            auth_data = opts[:auth_data] || []
            ticket = opts[:ticket]
            second_ticket = opts[:second_ticket] || ''

            cred = Rex::Proto::Kerberos::CredentialCache::Credential.new(
              client: client,
              server: server,
              key: key,
              time: time,
              is_skey: is_skey,
              tkt_flags:tkt_flags,
              addrs: addrs,
              auth_data: auth_data,
              ticket: ticket,
              second_ticket: second_ticket
            )

            cred
          end
        end
      end
    end
  end
end
