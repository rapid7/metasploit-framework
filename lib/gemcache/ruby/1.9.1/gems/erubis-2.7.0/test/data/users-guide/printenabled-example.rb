require 'erubis'
class PrintEnabledEruby < Erubis::Eruby
  include Erubis::PrintEnabledEnhancer
end
input = File.read('printenabled-example.eruby')
eruby = PrintEnabledEruby.new(input)
list = ['aaa', 'bbb', 'ccc']
print eruby.evaluate(:list=>list)
