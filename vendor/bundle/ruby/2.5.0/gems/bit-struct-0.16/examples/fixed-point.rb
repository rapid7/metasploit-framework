require 'bit-struct'

class C < BitStruct
  unsigned    :f1,  3,  :fixed => 100
  unsigned    :f2,  5,  :fixed => 1000
  unsigned    :f3,  8,  :fixed => 10000
  unsigned    :f4, 32,  :fixed => 100000
end

c = C.new

c.f1 =      0.03
c.f2 =      0.005
c.f3 =      0.0144
c.f4 =    456.78912

p c  # ==> #<C f1=0.03, f2=0.005, f3=0.0144, f4=456.78912>
