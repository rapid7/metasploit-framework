require 'backports/tools/make_block_optional'

Backports.make_block_optional ENV, :delete_if, :test_on => ENV
