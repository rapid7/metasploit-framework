# -*- coding: binary -*-

require 'bindata'

require 'rex/proto/kerberos/credential_cache/primitive'

module Rex::Proto::Kerberos::CredentialCache
  class Krb5CcacheCredentialAuthdata < BinData::Record
    endian :big
    search_prefix :krb5_ccache

    uint16        :ad_type
    data          :data
  end
end
