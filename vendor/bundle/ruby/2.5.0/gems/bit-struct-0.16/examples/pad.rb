require 'bit-struct'

class PadTest < BitStruct
  unsigned :x,    3
  pad      :p1,   2
  unsigned :y,    3
end

pt = PadTest.new
pt.x = 1
pt.y = 2

p pt
y pt
