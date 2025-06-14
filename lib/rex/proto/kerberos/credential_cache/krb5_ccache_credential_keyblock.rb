# -*- coding: binary -*-

require 'bindata'

require 'rex/proto/kerberos/credential_cache/primitive'

module Rex::Proto::Kerberos::CredentialCache
  class Krb5CcacheCredentialKeyblock < BinData::Record
    endian :big
    search_prefix :krb5_ccache

    # @see Rex::Proto::Kerberos::Crypto::Encryption
    uint16        :enctype
    data          :data
  end
end
