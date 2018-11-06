require 'backports/tools/make_block_optional'

Backports.make_block_optional ENV, :each_value, :test_on => ENV
