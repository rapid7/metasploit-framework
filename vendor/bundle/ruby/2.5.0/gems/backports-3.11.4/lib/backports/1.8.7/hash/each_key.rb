require 'backports/tools/make_block_optional'

Backports.make_block_optional Hash, :each_key, :test_on => {:hello => "world!"}
