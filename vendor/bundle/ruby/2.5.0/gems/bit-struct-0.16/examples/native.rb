require 'bit-struct'

class NativeNumbers < BitStruct

  unsigned   :x0,    1,   :endian => :native
  unsigned   :x1,    13,  :endian => :native
  unsigned   :x2,    2,   :endian => :native
  unsigned   :x3,    32,  :endian => :native

  float      :f1,    32,  :endian => :native
  float      :f2,    64,  :endian => :native
  float      :f3,    32
  float      :f4,    64

  default_options :endian => :native
    # affects fields defined after this and in subclasses

  unsigned    :y1,   32

end

n = NativeNumbers.new
p n
n.x1 = 5
n.f1 = n.f3 = 1234.567
n.f2 = n.f4 = 6543.321
n.y1 = 1

p n
p n.unpack("C*")

