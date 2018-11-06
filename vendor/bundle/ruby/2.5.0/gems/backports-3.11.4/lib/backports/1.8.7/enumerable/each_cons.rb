require 'backports/tools/make_block_optional'
require 'enumerator' unless Enumerable.method_defined? :each_cons

Backports.make_block_optional Enumerable, :each_cons, :test_on => 1..2, :arg => 1
