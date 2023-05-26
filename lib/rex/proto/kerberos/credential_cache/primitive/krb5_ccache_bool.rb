# -*- coding: binary -*-

require 'bindata'

module Rex::Proto::Kerberos::CredentialCache::Primitive
  class Krb5CcacheBool < BinData::Primitive
    endian :big

    uint8 :data

    def get
      self.data != 0
    end

    def set(v)
      self.data = v ? 1 : 0
    end
  end
end
