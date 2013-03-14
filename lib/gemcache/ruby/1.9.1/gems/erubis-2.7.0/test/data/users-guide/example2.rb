require 'erubis'
input = File.read('example2.eruby')
eruby = Erubis::Eruby.new(input, :trim=>false)

puts "----- script source ---"
puts eruby.src                            # print script source

puts "----- result ----------"
list = ['aaa', 'bbb', 'ccc']
puts eruby.result(binding())              # get result
