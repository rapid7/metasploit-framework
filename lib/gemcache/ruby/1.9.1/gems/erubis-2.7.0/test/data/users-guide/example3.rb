require 'erubis'
input = File.read('example3.eruby')
eruby = Erubis::EscapedEruby.new(input)    # or Erubis::XmlEruby

puts "----- script source ---"
puts eruby.src                             # print script source

puts "----- result ----------"
list = ['<aaa>', 'b&b', '"ccc"']
puts eruby.result(binding())               # get result
