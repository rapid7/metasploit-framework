# -*- coding: binary -*-

require 'bindata'

require 'rex/proto/kerberos/credential_cache/primitive'

module Rex::Proto::Kerberos::CredentialCache::Primitive
  class Krb5CcacheEpoch < BinData::Primitive
    endian :big

    uint32 :epoch

    def get
      Time.at(self.epoch)
    end

    def set(v)
      self.epoch = v.to_i
    end
  end
end
