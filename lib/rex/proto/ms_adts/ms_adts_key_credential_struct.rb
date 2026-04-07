# -*- coding: binary -*-

require 'bindata'
require 'rex/proto/ms_adts/ms_adts_key_credential_entry_struct'

module Rex::Proto::MsAdts
  class MsAdtsKeyCredentialStruct < BinData::Record
    endian :little

    uint32              :version

    array               :credential_entries, type: :ms_adts_key_credential_entry_struct, read_until: :eof
  end
end
