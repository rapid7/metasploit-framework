require 'bit-struct'

class NestedPart < BitStruct
  unsigned :x,    5
  unsigned :y,    3
  char     :s,  5*8
end

class Container < BitStruct
  nest    :n1,  NestedPart, "Nest 1"
  nest    :n2,  NestedPart, "Nest 2"
end

cont = Container.new

n = NestedPart.new(:x=>1, :y=>2, :s=>"abc")

p n

cont.n1 = n

n.x = 5
n.y = 0
n.s = " xyz "

cont.n2 = n # note copy semantics here!

puts
p cont
puts
puts cont.inspect_detailed

puts "-"*80
