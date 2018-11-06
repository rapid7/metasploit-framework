require 'erubis'
eruby = Erubis::Eruby.new(File.read('template1.rhtml'))
items = ['foo', 'bar', 'baz']
x = 1
## local variable 'x' and 'eruby' are passed to template as well as 'items'!
print eruby.result(binding())    
## local variable 'x' is changed unintendedly because it is changed in template!
puts "** debug: x=#{x.inspect}"  #=> "baz"
