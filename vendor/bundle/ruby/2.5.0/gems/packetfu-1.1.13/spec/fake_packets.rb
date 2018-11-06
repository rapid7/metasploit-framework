module FakePacket
  def layer
    7
  end
end

class PacketFu::FooPacket < PacketFu::Packet
  extend FakePacket
end

class PacketFu::BarPacket < PacketFu::Packet
  extend FakePacket
end

class PacketBaz
end

def add_fake_packets
  PacketFu.add_packet_class(PacketFu::FooPacket)
  PacketFu.add_packet_class(PacketFu::BarPacket)
end

def remove_fake_packets
  PacketFu.remove_packet_class(PacketFu::FooPacket)
  PacketFu.remove_packet_class(PacketFu::BarPacket)
end

remove_fake_packets
