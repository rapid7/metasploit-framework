require 'backports/tools/make_block_optional'

Backports.make_block_optional Hash, :reject, :reject!, :test_on => {:hello => "world!"}
