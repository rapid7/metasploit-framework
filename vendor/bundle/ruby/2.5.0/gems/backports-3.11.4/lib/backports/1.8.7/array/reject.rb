require 'backports/tools/make_block_optional'

Backports.make_block_optional Array, :reject, :reject!, :test_on => [42]
