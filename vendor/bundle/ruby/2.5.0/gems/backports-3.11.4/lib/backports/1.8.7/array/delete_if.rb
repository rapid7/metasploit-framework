require 'backports/tools/make_block_optional'

Backports.make_block_optional Array, :delete_if, :test_on => [42]
