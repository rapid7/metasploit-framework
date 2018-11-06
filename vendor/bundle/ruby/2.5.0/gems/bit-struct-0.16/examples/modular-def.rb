# This example shows how to refactor a BitStruct class defininition
# using modules.

module ModuleMethodSaver
  def method_missing(meth, *args, &block)
    @saved ||= []
    @saved << [meth, args, block]
  end

  def included(m)
    if @saved
      @saved.each do |meth, args, block|
        m.send(meth, *args, &block)
      end
    end
  end
end


require 'bit-struct'

module M
  extend ModuleMethodSaver

  unsigned  :x, 13
  signed    :y, 7
end

class BS < BitStruct
  include M
end


bs = BS.new
bs.x = 123
bs.y = -63

p bs  # ==> #<BS x=123, y=-63>
