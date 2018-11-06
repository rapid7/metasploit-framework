require 'bit-struct' # http://redshift.sourceforge.net/bit-struct

class Bits < BitStruct
  unsigned    :bit0,     1,     "Foo bit"
  unsigned    :bit1,     1,     "Bar bit"
  unsigned    :bit2,     1
  unsigned    :bit3,     1
  unsigned    :bit4,     1
  unsigned    :bit5,     1
  unsigned    :bit6,     1
  unsigned    :bit7,     1
end

b = Bits.new

b.bit3 = 1
p b.bit3 # ==> 1
p b.bit4 # ==> 0

