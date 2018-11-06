require 'backports/tools/make_block_optional'
Backports.make_block_optional Enumerable, :map, :test_on => 1..2
Backports.make_block_optional Array, :map, :test_on => [1, 2]

