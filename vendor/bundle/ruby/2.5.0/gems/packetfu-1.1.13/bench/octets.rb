require 'benchmark'
$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'

IPV4_RAW = "\x01\x02\x03\x04"
IPV4_STR = "1.2.3.4"


iters = 50_000
Benchmark.bm do |bm|
  bm.report("Octets.new.read(...)         ") {iters.times {PacketFu::Octets.new.read(IPV4_RAW)}}
  bm.report("Octets.new.read_quad(...)    ") {iters.times {PacketFu::Octets.new.read_quad(IPV4_STR)}}

  octets = PacketFu::Octets.new
  bm.report("octets#read(...)             ") {iters.times {octets.read(IPV4_RAW)}}
  bm.report("octets#read_quad(...)        ") {iters.times {octets.read_quad(IPV4_STR)}}

  octets.read(IPV4_RAW)
  bm.report("octets#to_x()                ") {iters.times {octets.to_x}}
  bm.report("octets#to_i()                ") {iters.times {octets.to_i}}
  bm.report("octets#to_s()                ") {iters.times {octets.to_s}}
end
