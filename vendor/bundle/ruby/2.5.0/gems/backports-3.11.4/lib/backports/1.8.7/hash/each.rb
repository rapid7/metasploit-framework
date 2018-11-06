require 'backports/tools/make_block_optional'

Backports.make_block_optional Hash, :each, :test_on => {:hello => "world!"}
