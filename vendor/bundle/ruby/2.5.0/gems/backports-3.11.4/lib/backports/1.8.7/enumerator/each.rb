unless Object.const_defined? :Enumerator
  require 'backports/tools/make_block_optional'
  require 'enumerator'

  Backports.make_block_optional Enumerable::Enumerator, :each, :test_on => [42].to_enum
end
