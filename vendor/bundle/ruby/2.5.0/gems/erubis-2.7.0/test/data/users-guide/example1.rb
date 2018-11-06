require 'erubis'
input = File.read('example1.eruby')
eruby = Erubis::Eruby.new(input)    # create Eruby object

puts "---------- script source ---"
puts eruby.src                      # print script source

puts "---------- result ----------"
list = ['aaa', 'bbb', 'ccc']
puts eruby.result(binding())        # get result
## or puts eruby.result(:list=>list)  # or pass Hash instead of Binding

## # or
## eruby = Erubis::Eruby.new
## input = File.read('example1.eruby')
## src = eruby.convert(input)
## eval src
