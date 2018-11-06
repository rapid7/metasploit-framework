require 'erubis'
input = File.read('example5.eruby')
eruby = Erubis::Eruby.new(input)      # create Eruby object

## create context object
## (key means var name, which may be string or symbol.)
context = {
  :val   => 'Erubis Example',
  'list' => ['aaa', 'bbb', 'ccc'],
}
## or
# context = Erubis::Context.new()
# context['val'] = 'Erubis Example'
# context[:list] = ['aaa', 'bbb', 'ccc'],

puts eruby.evaluate(context)         # get result
