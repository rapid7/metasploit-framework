require 'bit-struct'

class C < BitStruct
  unsigned    :x, 80, :endian => :big, :fixed => 1_000_000_000
  unsigned    :y, 24, :endian => :native, :format => "0x%x"
  unsigned    :z, 64, :format => "0x%x" # big-endian by default
  signed      :w, 48
end

c = C.new

c.x = 1.000_000_001
c.y = 0xa00002
c.z = 0x1234abcd5678efef
c.w = -1

p c
#puts c.unpack("H*")
