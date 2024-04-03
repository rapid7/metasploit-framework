# -*- coding: binary -*-

require 'bindata'

module Rex::Proto
  class BcryptPublicKey < BinData::Record
    endian :little

    uint32              :magic
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

