require 'erubis'

class PrefixedLineEruby < Erubis::Eruby
  include Erubis::PrefixedLineEnhancer
end

input = File.read('prefixedline-example.rhtml')
eruby = PrefixedLineEruby.new(input, :prefixchar=>'!')  # default '%'
print eruby.src
