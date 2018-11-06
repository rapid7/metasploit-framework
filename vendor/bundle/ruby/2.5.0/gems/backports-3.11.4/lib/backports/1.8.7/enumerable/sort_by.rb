require 'backports/tools/make_block_optional'

Backports.make_block_optional Enumerable, :sort_by, :test_on => 1..2
