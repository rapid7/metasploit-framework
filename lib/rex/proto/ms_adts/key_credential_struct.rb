# -*- coding: binary -*-

require 'bindata'
require 'rex/proto/ms_adts/key_credential_entry_struct'

module Rex::Proto::MsAdts
  class KeyCredentialStruct < BinData::Record
    endian :little

    uint32              :version

    array               :credential_entries, type: :key_credential_entry_struct, read_until: :eof
  end
end
