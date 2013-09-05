# -*- coding: binary -*-
module Rex
module Proto
module DCERPC
module WDSCP
class Packet

  WDS_CONST 	= Rex::Proto::DCERPC::WDSCP::Constants

  def initialize(packet_type, opcode)
    if opcode.nil? || packet_type.nil?
      raise(ArgumentError, "Packet arguments cannot be nil")
    end

    @variables = []
    @packet_type = WDS_CONST::PACKET_TYPE[packet_type]
    @opcode = WDS_CONST::OPCODE[opcode]
  end

  def add_var(name, type_mod=0, value_length=nil, array_size=0, value)
    padding = 0
    value_type = WDS_CONST::BASE_TYPE[WDS_CONST::VAR_TYPE_LOOKUP[name]]
    name = Rex::Text.to_unicode(name).unpack('H*')[0]

    value_length ||= value.length

    # Variable block total size should be evenly divisible by 16.
    len = 16 * (1 + (value_length/16))
    @variables << 
      [	name,
        padding,
        value_type,
        type_mod,
        value_length,
        array_size,
        value
      ].pack('H132vvvVVa%i' % len)
  end

  def create
    packet = []
    var_count = @variables.count

    packet_size = 0
    @variables.each do |var|
      packet_size += var.length
    end

    # variables + operation
    packet_size += 16

    # These bytes are not part of the spec but are not part of DCERPC according to Wireshark
    # Perhaps something from MSRPC specific? Basically length of the WDSCP packet twice...
    packet << Rex::Text.pack_int64le(packet_size+40)*2
    packet << create_endpoint_header(packet_size)
    packet << create_operation_header(packet_size, var_count, @packet_type, @opcode)
    packet.concat(@variables)

    return packet.join
  end

  def create_operation_header(packet_size, var_count, packet_type=:REQUEST, opcode)
    return 	[	packet_size, # PacketSize
        256,         # Version
        packet_type, # Packet_Type
        0,           # Padding
        opcode,      # Opcode
        var_count,   # Variable Count
      ].pack('VvCCVV')
  end

  def create_endpoint_header(packet_size)
    return [	40,                            # Header_Size
        256,                           # Version
        packet_size,                   # Packet_Size - This doesn't differ from operation header despite the spec...
        WDS_CONST::OS_DEPLOYMENT_GUID, # GUID
        "\x00"*16,                     # Reserved
      ].pack('vvVa16a16')
  end
end
end
end
end
end
