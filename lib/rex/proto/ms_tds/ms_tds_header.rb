# -*- coding: binary -*-

require 'bindata'

module Rex::Proto::MsTds
  class MsTdsHeader < BinData::Record
    endian :big

    ms_tds_type    :packet_type
    ms_tds_status  :status, initial_value: MsTdsStatus::END_OF_MESSAGE
    uint16         :packet_length, initial_value: 8
    uint16         :spid
    uint8          :packet_id
    uint8          :window
  end
end