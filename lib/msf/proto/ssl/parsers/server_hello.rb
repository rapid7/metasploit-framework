  # -*- coding: binary -*-

module Msf::Proto::SSL::Parsers

  # Parse Server Hello message
  def parse_server_hello(data)
    version = data.unpack('H4')[0]
    vprint_debug("\t\tServer Hello Version:           0x#{version}")
    random = data[2,32].unpack('H*')[0]
    vprint_debug("\t\tServer Hello random data:       #{random}")
    session_id_length = data[34,1].unpack('C')[0]
    vprint_debug("\t\tServer Hello Session ID length: #{session_id_length}")
    session_id = data[35,session_id_length].unpack('H*')[0]
    vprint_debug("\t\tServer Hello Session ID:        #{session_id}")
    # TODO Read the rest of the server hello (respect message length)

    # TODO: return hash with data
    true
  end
end
