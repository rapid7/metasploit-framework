require 'backports/tools/make_block_optional'

Backports.make_block_optional Enumerable, :find_all, :test_on => 1..2
