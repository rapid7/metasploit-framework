  # -*- coding: binary -*-

module Msf::Proto::SSL::Parsers

  # Parse SSL header
  def parse_ssl_record(data)
    ssl_records = []
    remaining_data = data
    ssl_record_counter = 0
    while remaining_data && remaining_data.length > 0
      ssl_record_counter += 1
      ssl_unpacked = remaining_data.unpack('CH4n')
      return nil if ssl_unpacked.nil? or ssl_unpacked.length < 3
      ssl_type = ssl_unpacked[0]
      ssl_version = ssl_unpacked[1]
      ssl_len = ssl_unpacked[2]
      vprint_debug("SSL record ##{ssl_record_counter}:")
      vprint_debug("\tType:    #{ssl_type}")
      vprint_debug("\tVersion: 0x#{ssl_version}")
      vprint_debug("\tLength:  #{ssl_len}")
      if ssl_type != Msf::Proto::SSL::RECORD_TYPE_HANDSHAKE
        vprint_debug("\tWrong Record Type! (#{ssl_type})")
      else
        ssl_data = remaining_data[5, ssl_len]
        handshakes = parse_handshakes(ssl_data)
        ssl_records << {
            :type => ssl_type,
            :version => ssl_version,
            :length => ssl_len,
            :data => handshakes
        }
      end
      remaining_data = remaining_data[(ssl_len + 5)..-1]
    end

    ssl_records
  end
end
