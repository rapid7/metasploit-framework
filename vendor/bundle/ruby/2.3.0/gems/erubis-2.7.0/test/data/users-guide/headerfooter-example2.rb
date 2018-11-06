require 'erubis'
class HeaderFooterEruby < Erubis::Eruby
  include Erubis::HeaderFooterEnhancer
end

input = File.read('headerfooter-example2.rhtml')
eruby = HeaderFooterEruby.new(input)
print eruby.src
