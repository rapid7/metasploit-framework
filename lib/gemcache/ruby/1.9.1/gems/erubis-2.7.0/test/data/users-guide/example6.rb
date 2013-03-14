class MyData
  attr_accessor :val, :list
end

## any object can be a context object
mydata = MyData.new
mydata.val = 'Erubis Example'
mydata.list = ['aaa', 'bbb', 'ccc']

require 'erubis'
eruby = Erubis::Eruby.new(File.read('example5.eruby'))
puts eruby.evaluate(mydata)
