require 'backports/tools/make_block_optional'

if RUBY_VERSION < '1.8.7'
  Backports.make_block_optional IO, :each_byte, :force => true
  IO.send :alias_method, :bytes, :each_byte
end
