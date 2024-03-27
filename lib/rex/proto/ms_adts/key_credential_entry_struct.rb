
# -*- coding: binary -*-

require 'bindata'

module Rex::Proto::MsAdts
  class KeyCredentialEntryStruct < BinData::Record
    endian :little

    uint16              :struct_length
    uint8               :identifier
    string              :data, length: :struct_length
  end
end
