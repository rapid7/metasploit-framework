require 'backports/tools/make_block_optional'

Backports.make_block_optional ENV, :reject, :test_on => ENV
Backports.make_block_optional ENV, :reject!, :test_on => ENV
