require './ip'

class Point < BitStruct
  unsigned    :x,   16
  unsigned    :y,   16
  unsigned    :z,   16
end

class MyPacket < IP
  rest    :point, Point   # treat this field as Point
end

packet = MyPacket.new
point = Point.new({:x=>1, :y=>2, :z=>3})
packet.point = point

p point
p packet.point
p packet

puts packet.inspect_detailed
puts "-" * 60

require 'yaml'

packet_yaml = packet.to_yaml
puts packet_yaml

packet2 = YAML.load( packet_yaml)
p packet2
