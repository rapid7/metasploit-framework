require 'erubis'
input = File.read('fasteruby.rhtml')
eruby = Erubis::FastEruby.new(input)    # create Eruby object

puts "---------- script source ---"
puts eruby.src

puts "---------- result ----------"
context = { :title=>'Example', :list=>['aaa', 'bbb', 'ccc'] }
output = eruby.evaluate(context)
print output
