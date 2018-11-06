require 'backports/tools/make_block_optional'

Backports.make_block_optional ARGF, :each_line, :force => true if RUBY_VERSION < '1.8.7'
