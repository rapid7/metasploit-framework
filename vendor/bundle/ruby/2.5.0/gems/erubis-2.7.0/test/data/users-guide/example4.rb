require 'erubis'
input = File.read('example4.eruby')
eruby = Erubis::Eruby.new(input, :pattern=>'<!--% %-->')
                                      # or '<(?:!--)?% %(?:--)?>'

puts "---------- script source ---"
puts eruby.src                            # print script source

puts "---------- result ----------"
list = ['aaa', 'bbb', 'ccc']
puts eruby.result(binding())              # get result
