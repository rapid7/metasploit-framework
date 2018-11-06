require 'bit-struct'

class Container < BitStruct
  nest    :n,  "Nest" do
    unsigned :x,    5
    unsigned :y,    3
    char     :s,  5*8
  end
end

cont = Container.new

n = cont.n

n.x = 5
n.y = 0
n.s = " xyz "

cont.n = n # note copy semantics here!

p cont
puts
puts cont.inspect_detailed
