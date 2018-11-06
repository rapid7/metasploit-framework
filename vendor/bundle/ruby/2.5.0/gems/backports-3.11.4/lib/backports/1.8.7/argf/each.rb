require 'backports/tools/make_block_optional'

Backports.make_block_optional ARGF, :each, :force => true if RUBY_VERSION < '1.8.7'
