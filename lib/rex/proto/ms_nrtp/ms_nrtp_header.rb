require 'rex/proto/ms_nrtp/ms_nrtp_counted_string'

module Rex::Proto::MsNrtp::MsNrtpHeader
  class MsNrtpHeaderEnd < BinData::Record
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrtp/32803cc9-e5d2-4d76-8852-b2eba3af25ca
    TOKEN = 0
    endian :little
  end

  class MsNrtpHeaderCustom < BinData::Record
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrtp/709beed5-da49-45b0-bf1b-836da17352c3
    TOKEN = 1
    endian :little

    ms_nrtp_counted_string :header_name
    ms_nrtp_counted_string :header_value
  end

  class MsNrtpHeaderStatusCode < BinData::Record
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrtp/70cdb0d8-6a58-46ae-8cb0-6976a9c3720e
    TOKEN = 2
    endian :little

    uint8  :data_type, value: 2
    uint16 :status_code_value
  end

  class MsNrtpHeaderStatusPhrase < BinData::Record
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrtp/a9a0e845-56ba-4b4a-9561-93940f039150
    TOKEN = 3
    endian :little

    uint8                  :data_type, value: 1
    ms_nrtp_counted_string :status_phrase_value
  end

  class MsNrtpHeaderUri < BinData::Record
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrtp/2b1b47f7-4fed-4515-a0f9-e0688664c728
    TOKEN = 4
    endian :little

    uint8                  :data_type, value: 1
    ms_nrtp_counted_string :uri_value
  end

  class MsNrtpHeaderCloseConnection < BinData::Record
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrtp/f94572e8-c821-42a2-8b0f-dabe1cbc7e02
    TOKEN = 5
    endian :little

    uint8 :data_type, value: 0
  end

  class MsNrtpHeaderContentType < BinData::Record
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrtp/d128389c-7cf6-4f09-9928-287324836344
    TOKEN = 6
    endian :little

    uint8                  :data_type, value: 1
    ms_nrtp_counted_string :content_type_value
  end

  class MsNrtpHeaderUnknown < BinData::Record
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrtp/1cb3cf86-2a42-4f38-bfda-f4f546c629f5
    endian :little

    uint8  :data_type
    choice :data_value, selection: :data_type, onlyif: -> { data_type != 0 } do
      ms_nrtp_counted_string 1
      uint8                  2
      uint16                 3
      int32                  4
    end
  end

  class MsNrtpHeader < BinData::Record
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrtp/c9a3ae3b-f50f-4b02-8540-964b59918291
    endian :little

    uint16 :token
    choice :header, selection: :token do
      ms_nrtp_header_end              MsNrtpHeaderEnd::TOKEN
      ms_nrtp_header_custom           MsNrtpHeaderCustom::TOKEN
      ms_nrtp_header_status_code      MsNrtpHeaderStatusCode::TOKEN
      ms_nrtp_header_status_phrase    MsNrtpHeaderStatusPhrase::TOKEN
      ms_nrtp_header_uri              MsNrtpHeaderUri::TOKEN
      ms_nrtp_header_close_connection MsNrtpHeaderCloseConnection::TOKEN
      ms_nrtp_header_content_type     MsNrtpHeaderContentType::TOKEN
      ms_nrtp_header_unknown          :default
    end
  end
end
