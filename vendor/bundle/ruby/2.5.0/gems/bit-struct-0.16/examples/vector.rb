require 'bit-struct'

# Example 1
class Vec < BitStruct::Vector
  # these declarations apply to *each* entry in the vector:
  unsigned :x,  16
  signed   :y,  32

  Entry = struct_class # Give it a name, just for inspect to look nice
end

v = Vec.new(5) # explicit length
entry = v[3]
entry.x = 2
v[3] = entry

entry = v[4]
entry.y = -4
v[4] = entry

entry.x = 42
v << entry

p v
puts

v2 = Vec.new(v) # determines length from argument
p v2
puts

# Example 2
class Vec2 < BitStruct::Vector
  class Entry < BitStruct
    unsigned :x,  16
    signed   :y,  32
  end

  struct_class Entry # use Entry as the struct_class for Vec2
end

v = Vec2.new(5) # explicit length
entry = v[3]
entry.x = 2
v[3] = entry

entry = v[4]
entry.y = -4
v[4] = entry

p v
puts

puts v.inspect_detailed
puts

puts Vec2.describe

# Example 3: inheritance
class VecSub < Vec2
  float :z, 32
end

vsub = VecSub.new(3)
entry = vsub[1]
entry.x = 12
entry.y = -1
entry.z = 4.5
vsub[1] = entry
p vsub
puts

# Example 4: vector field in a bitstruct
class Packet < BitStruct
  unsigned :stuff, 32, "whatever"

  # Using the Vec class defined above
  vector  :v, Vec, "a vector", 5

  # equivalently, using an anonymous subclass of BitStruct::Vector
  vector :v2, "a vector 2", 5 do
    unsigned :x,  16
    signed   :y,  32
  end
end

pkt = Packet.new
  vec = pkt.v
    entry = vec[2]
      entry.x = 123
      entry.y = -456
    vec[2] = entry
  pkt.v = vec
p pkt, pkt.v, pkt.v[2], pkt.v[2].y
puts
puts pkt.inspect_detailed
puts

puts Packet.describe(:expand => true)
