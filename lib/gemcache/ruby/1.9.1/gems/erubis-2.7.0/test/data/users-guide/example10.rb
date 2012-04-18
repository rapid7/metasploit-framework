require 'erubis'
input = File.read('example10.xhtml')
eruby = Erubis::PI::Eruby.new(input)
print eruby.src
