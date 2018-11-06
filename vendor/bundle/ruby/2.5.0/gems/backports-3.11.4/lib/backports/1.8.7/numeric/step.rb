require 'backports/tools/make_block_optional'

Backports.make_block_optional Numeric, :step, :test_on => 42, :arg => [100, 6]
