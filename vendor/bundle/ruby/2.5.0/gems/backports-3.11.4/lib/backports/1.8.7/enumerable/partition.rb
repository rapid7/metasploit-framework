require 'backports/tools/make_block_optional'

Backports.make_block_optional Enumerable, :partition, :test_on => 1..2
