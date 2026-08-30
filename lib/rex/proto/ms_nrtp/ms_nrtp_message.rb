require 'rex/proto/ms_nrtp/ms_nrtp_header'

module Rex::Proto::MsNrtp

  class MsNrtpMessage < BinData::Record
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrtp/750a0ae4-b3e7-4c0e-97b1-8b95cffd04c5
    endian :little

    uint32 :protocol_id, value: 0x54454E2E
    uint8  :major_version, initial_value: 1
    uint8  :minor_version, initial_value: 0
    uint16 :operation_type
    uint16 :content_distribution
    uint32 :content_length, onlyif: -> { content_distribution == 0 }
    array  :headers, type: :ms_nrtp_header, read_until: -> { element.token == MsNrtpHeader::MsNrtpHeaderEnd::TOKEN }
  end
end
