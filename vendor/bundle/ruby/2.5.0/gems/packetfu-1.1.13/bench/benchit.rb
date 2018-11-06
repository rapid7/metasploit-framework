$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'
require 'benchmark'
class String
  def bin
    self.scan(/../).map {|x| x.to_i(16).chr}.join
  end
end

file_pfx = ARGV.shift

IPV6_PACKET = "3333000000fb442a60c14d7b86dd60000000006611fffe80000000000000462a60fffec14d7bff0200000000000000000000000000fb14e914e900664ed1000000000002000000020000145542432d437573746f6d6572732d695061642d33056c6f63616c0000ff0001c00c00ff0001c00c001c0001000000780010fe80000000000000462a60fffec14d7bc00c0001000100000078000448d77827".bin

ARP_PACKET = "ffffffffffff001e6837bcf708060001080006040001001e6837bcf748d7780100000000000048d779f7000000000000000000000000000000000000".bin

UDP_PACKET = "01005e7ffffa100ba9eb63400800450000a12d7c0000011159b446a5fb7ceffffffacdf3076c008d516e4d2d534541524348202a20485454502f312e310d0a486f73743a3233392e3235352e3235352e3235303a313930300d0a53543a75726e3a736368656d61732d75706e702d6f72673a6465766963653a496e7465726e6574476174657761794465766963653a310d0a4d616e3a22737364703a646973636f766572220d0a4d583a330d0a0d0a".bin

TCP_PACKET = "e0f8472161a600254ba0760608004500004403554000400651d0c0a83207c0a832370224c1d22d94847f0b07c4ba8018ffff30ba00000101080a8731821433564b8c01027165000000000000200000000000".bin

iters = 5_000
data = []
data = []
data = []
data = []
puts "Parsing a TCP Packet..."
require 'pp'
Benchmark.bm do |bm|
  data << bm.report("PacketFu::Packet.parse()  ") { iters.times {PacketFu::Packet.parse(TCP_PACKET)} }
  data << bm.report("PacketFu::EthPacket.new.read()  ") { iters.times {PacketFu::EthPacket.new.read(TCP_PACKET)} }
  data << bm.report("PacketFu::IPPacket.new.read()  ") { iters.times {PacketFu::IPPacket.new.read(TCP_PACKET)} }
  data << bm.report("PacketFu::TCPPacket.new.read()  ") { iters.times {PacketFu::TCPPacket.new.read(TCP_PACKET)} }
  nil
end

puts ""
puts "Parsing a UDP Packet..."
Benchmark.bm do |bm|
  data << bm.report("PacketFu::Packet.parse()  ") { iters.times {PacketFu::Packet.parse(UDP_PACKET)} }
  data << bm.report("PacketFu::EthPacket.new.read()  ") { iters.times {PacketFu::EthPacket.new.read(UDP_PACKET)} }
  data << bm.report("PacketFu::IPPacket.new.read()  ") { iters.times {PacketFu::IPPacket.new.read(UDP_PACKET)} }
  data << bm.report("PacketFu::UDPPacket.new.read()  ") { iters.times {PacketFu::UDPPacket.new.read(UDP_PACKET)} }
  nil
end

puts ""
puts "Parsing a ARP Packet..."
Benchmark.bm do |bm|
  data << bm.report("PacketFu::Packet.parse()  ") { iters.times {PacketFu::Packet.parse(ARP_PACKET)} }
  data << bm.report("PacketFu::EthPacket.new.read()  ") { iters.times {PacketFu::EthPacket.new.read(ARP_PACKET)} }
  data << bm.report("PacketFu::ARPPacket.new.read()  ") { iters.times {PacketFu::ARPPacket.new.read(ARP_PACKET)} }
  nil
end

puts ""
puts "Parsing a IPv6 Packet..."
Benchmark.bm do |bm|
  data << bm.report("PacketFu::Packet.parse()  ") { iters.times {PacketFu::Packet.parse(IPV6_PACKET)} }
  data << bm.report("PacketFu::EthPacket.new.read()  ") { iters.times {PacketFu::EthPacket.new.read(IPV6_PACKET)} }
  data << bm.report("PacketFu::IPv6Packet.new.read()  ") { iters.times {PacketFu::IPv6Packet.new.read(IPV6_PACKET)} }
  nil
end
if file_pfx
  filename = "#{file_pfx}.dat"
  puts "dumping data to #{filename}"
  fio = File.open(filename, "w")
  Marshal.dump(data, fio)
  fio.close
end
