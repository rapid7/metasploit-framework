require 'backports/tools/make_block_optional'

Backports.make_block_optional Hash, :delete_if, :test_on => {:hello => "world!"}
