require 'erubis'
input = File.read('example9.eruby')
eruby1 = Erubis::Eruby.new(input)
eruby2 = Erubis::Eruby.new(input, :preamble=>false, :postamble=>false)

puts eruby1.src   # print preamble and postamble
puts "--------------"
puts eruby2.src   # don't print preamble and postamble
