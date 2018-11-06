require 'backports/tools/make_block_optional'

Backports.make_block_optional Struct, :each, :test_on => Struct.new(:foo, :bar).new
