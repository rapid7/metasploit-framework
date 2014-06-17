  # -*- coding: binary -*-

module Msf::Proto::SSL

  # Generates a heartbeat request
  def heartbeat_request(length)
    payload = "\x01"              # Heartbeat Message Type: Request (1)
    payload << [length].pack('n') # Payload Length: 65535

    ssl_record(RECORD_TYPE_HEARTBEAT, payload)
  end
end