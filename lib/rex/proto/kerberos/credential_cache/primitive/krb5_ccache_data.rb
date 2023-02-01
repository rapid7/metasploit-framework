# -*- coding: binary -*-

require 'bindata'

module Rex::Proto::Kerberos::CredentialCache::Primitive
  # Primitive used for generic, dynamically-lengthed data blocks.
  class Krb5CcacheData < BinData::Primitive
    endian :big
    default_parameter initial_value: ''

    uint32 :len,  value: -> { data.length }
    string :data, read_length: :len, initial_value: :initial_value

    def get
      self.data.snapshot
    end

    def set(v)
      self.data = v
    end
  end
end
