require 'backports/tools/make_block_optional'

Backports.make_block_optional String, :each_byte, :test_on => "abc"

Backports.alias_method String, :bytes, :each_byte
