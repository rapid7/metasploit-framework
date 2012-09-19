require 'erubis'
input = File.read('example.eruby')

puts "----- Erubis::Eruby -----"
print Erubis::Eruby.new(input).src

puts "----- Erubis::FastEruby -----"
print Erubis::FastEruby.new(input).src
