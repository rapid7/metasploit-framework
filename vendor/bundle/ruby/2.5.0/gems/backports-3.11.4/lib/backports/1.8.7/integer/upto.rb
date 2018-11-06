require 'backports/tools/make_block_optional'

Backports.make_block_optional Integer, :upto, :test_on => 42, :arg => 42
