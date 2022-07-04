# -*- coding: binary -*-

require 'bindata'

require 'rex/proto/kerberos/credential_cache/krb5_ccache_credential_address'
require 'rex/proto/kerberos/credential_cache/krb5_ccache_credential_authdata'
require 'rex/proto/kerberos/credential_cache/krb5_ccache_credential_keyblock'
require 'rex/proto/kerberos/credential_cache/krb5_ccache_principal'
require 'rex/proto/kerberos/credential_cache/primitive'

module Rex::Proto::Kerberos::CredentialCache
  class Krb5CcacheCredential < BinData::Record
    endian :big
    search_prefix :krb5_ccache

    principal           :client
    principal           :server
    credential_keyblock :keyblock
    epoch               :authtime
    epoch               :starttime
    epoch               :endtime
    epoch               :renew_till
    bool                :is_skey
    uint32              :ticket_flags
    uint32              :address_count, initial_value: -> { addresses.length }
    array               :addresses, initial_length: :address_count, type: :credential_address
    uint32              :authdata_count, initial_value: -> { authdatas.length }
    array               :authdatas, initial_length: :authdata_count, type: :credential_authdata
    data                :ticket
    data                :second_ticket
  end
end
