# -*- coding: binary -*-

require 'bindata'

module Rex::Proto
  # [_BCRYPT_RSAKEY_BLOB](https://github.com/tpn/winsdk-10/blob/9b69fd26ac0c7d0b83d378dba01080e93349c2ed/Include/10.0.14393.0/shared/bcrypt.h#L390)
  class BcryptPublicKey < BinData::Record
    MAGIC = 0x31415352
    endian :little

    uint32              :magic, initial_value: MAGIC
    uint32              :key_length
    uint32              :exponent_length, :value => lambda { exponent.length }
    uint32              :modulus_length, :value => lambda { modulus.length }
    uint32              :prime1_length, :value => lambda { prime1.length }
    uint32              :prime2_length, :value => lambda { prime2.length }

    string              :exponent, :read_length => :exponent_length
    string              :modulus, :read_length => :modulus_length
    string              :prime1, :read_length => :prime1_length
    string              :prime2, :read_length => :prime2_length
  end
end

