require 'backports/tools/make_block_optional'

Backports.make_block_optional Enumerable, :each_with_index, :test_on => 1..2
