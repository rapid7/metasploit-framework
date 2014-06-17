# -*- coding: binary -*-

module Msf::Proto::SSL::Parsers

  # Parse Handshake data returned from servers
  def parse_handshakes(data)
    # Can contain multiple handshakes
    remaining_data = data
    handshakes = []
    handshake_count = 0
    while remaining_data && remaining_data.length > 0
      hs_unpacked = remaining_data.unpack('CCn')
      next if hs_unpacked.nil? or hs_unpacked.length < 3
      hs_type = hs_unpacked[0]
      hs_len_pad = hs_unpacked[1]
      hs_len = hs_unpacked[2]
      hs_data = remaining_data[4, hs_len]
      handshake_count += 1
      vprint_debug("\tHandshake ##{handshake_count}:")
      vprint_debug("\t\tLength: #{hs_len}")

      handshake_parsed = nil
      case hs_type
        when Msf::Proto::SSL::HANDSHAKE_TYPE_SERVER_HELLO
          vprint_debug("\t\tType:   Server Hello (#{hs_type})")
          handshake_parsed = parse_server_hello(hs_data)
        when Msf::Proto::SSL::HANDSHAKE_TYPE_CERTIFICATE
          vprint_debug("\t\tType:   Certificate Data (#{hs_type})")
          handshake_parsed = parse_certificate_data(hs_data)
        when Msf::Proto::SSL::HANDSHAKE_TYPE_KEY_EXCHANGE
          vprint_debug("\t\tType:   Server Key Exchange (#{hs_type})")
          # handshake_parsed = parse_server_key_exchange(hs_data)
        when Msf::Proto::SSL::HANDSHAKE_TYPE_SERVER_HELLO_DONE
          vprint_debug("\t\tType:   Server Hello Done (#{hs_type})")
        else
          vprint_debug("\t\tType:   Handshake type #{hs_type} not implemented")
      end

      handshakes << {
          :type     => hs_type,
          :len      => hs_len,
          :data     => handshake_parsed
      }
      remaining_data = remaining_data[(hs_len + 4)..-1]
    end

    handshakes
  end
end
