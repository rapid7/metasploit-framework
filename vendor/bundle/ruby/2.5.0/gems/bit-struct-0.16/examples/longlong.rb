require 'bit-struct'

class MyPacket < BitStruct
  unsigned :x, 8*8, "The x field", :endian => :network
    # :network is the default, and it's the same as :big
  unsigned :y, 8*8, "The y field", :endian => :little
end

pkt = MyPacket.new
pkt.x = 59843759843759843
pkt.y = 59843759843759843

p pkt.x  # 59843759843759843
p pkt.y  # 59843759843759843

p pkt
# #<MyPacket x=59843759843759843, y=59843759843759843>
p pkt.to_s
# "\000\324\233\225\037\202\326\343\343\326\202\037\225\233\324\000"

puts pkt.inspect_detailed
# MyPacket:
#                    The x field = 59843759843759843
#                    The y field = 59843759843759843

puts MyPacket.describe
#     byte: type         name          [size] description
# ----------------------------------------------------------------------
#       @0: unsigned     x             [  8B] The x field
#       @8: unsigned     y             [  8B] The y field
