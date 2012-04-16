require 'erubis'
s = "hello <%= name %>"
eruby = Erubis::Eruby.new(s)
filename = 'hello.rhtml'

## define instance method to Dummy class (or module)
class Dummy; end
eruby.def_method(Dummy, 'render(name)', filename)  # filename is optional
p Dummy.new.render('world')    #=> "hello world"

## define singleton method to dummy object
obj = Object.new
eruby.def_method(obj, 'render(name)', filename)    # filename is optional
p obj.render('world')          #=> "hello world"
