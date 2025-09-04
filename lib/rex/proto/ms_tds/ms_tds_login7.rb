module Rex::Proto::MsTds
  # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/773a62b6-ee89-4c02-9e5e-344882630aac
  class MsTdsLogin7 < BinData::Record
    endian :little

    uint32  :packet_length
    ms_tds_version  :tds_version, initial_value: MsTdsVersion::VERSION_7_1
    uint32  :packet_size
    uint32  :client_prog_ver
    uint32  :client_pid
    uint32  :connection_id

    struct  :option_flags_1 do
      bit1  :f_set_lang
      bit1  :f_database
      bit1  :f_use_db
      bit1  :f_dump_load
      bit2  :f_float
      bit1  :f_char
      bit1  :f_byte_order
    end

    struct  :option_flags_2 do
      bit1  :f_int_security
      bit3  :f_user_type
      bit1  :f_tran_boundary
      bit1  :f_cache_connect
      bit1  :f_odbc
      bit1  :f_language
    end

    struct  :type_flags do
      bit2  :f_reserved
      bit1  :f_read_only_intent
      bit1  :f_oledb
      bit4  :f_sql_type
    end

    struct  :option_flags_3 do
      bit3  :f_reserved
      bit1  :f_extension
      bit1  :f_unknown_collation_handling
      bit1  :f_user_instance
      bit1  :f_send_yukon_binary_xml
      bit1  :f_change_password
    end

    uint32  :client_time_zone
    uint32  :client_lcid

    # Offset/Length pairs for variable-length data
    uint16  :ib_hostname
    uint16  :cch_hostname
    uint16  :ib_username
    uint16  :cch_username
    uint16  :ib_password
    uint16  :cch_password
    uint16  :ib_app_name
    uint16  :cch_app_name
    uint16  :ib_server_name
    uint16  :cch_server_name
    uint16  :ib_unused
    uint16  :cb_unused
    uint16  :ib_extension, onlyif: -> { tds_version >= MsTdsVersion::VERSION_7_4 }
    uint16  :cch_extension, onlyif: -> { tds_version >= MsTdsVersion::VERSION_7_4 }
    uint16  :ib_clt_int_name
    uint16  :cch_clt_int_name
    uint16  :ib_language
    uint16  :cch_language
    uint16  :ib_database
    uint16  :cch_database

    # Client MAC address (6 bytes)
    string  :client_id, length: 6

    # More offset/length pairs
    uint16  :ib_sspi
    uint16  :cch_sspi
    uint16  :ib_attach_db_file
    uint16  :cch_attach_db_file
    uint16  :ib_change_password, onlyif: -> { tds_version >= MsTdsVersion::VERSION_7_2 }
    uint16  :cch_change_password, onlyif: -> { tds_version >= MsTdsVersion::VERSION_7_2 }
    uint32  :cb_sspi_long, onlyif: -> { tds_version >= MsTdsVersion::VERSION_7_2 }
  end
end