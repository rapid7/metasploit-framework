require 'backports/tools/make_block_optional'

Backports.make_block_optional Integer, :downto, :test_on => 42, :arg => 42
