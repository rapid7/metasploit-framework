require 'backports/tools/make_block_optional'

Backports.make_block_optional Range, :step, :test_on => 69..666, :arg => 42
