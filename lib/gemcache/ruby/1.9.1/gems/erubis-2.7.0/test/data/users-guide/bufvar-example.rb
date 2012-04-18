require 'erubis'
input = File.read('example.eruby')

puts "----- default -----"
eruby = Erubis::FastEruby.new(input)
puts eruby.src

puts "----- with :bufvar option -----"
eruby = Erubis::FastEruby.new(input, :bufvar=>'@_out_buf')
print eruby.src
