require 'erubis'
eruby = Erubis::Eruby.new(File.read('template2.rhtml'))
items = ['foo', 'bar', 'baz']
x = 1
## only 'items' are passed to template
print eruby.evaluate(:items=>items)    
## local variable 'x' is not changed!
puts "** debug: x=#{x.inspect}"  #=> 1
