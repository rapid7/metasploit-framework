#!/usr/bin/ruby

$:.unshift(File.join('..', File.dirname(__FILE__)))

require 'test/unit'
require 'Rex/Transformer'

class Rex::Transformer::UnitTest < Test::Unit::TestCase
	class Pizza
		def Pizza.from_s(str)
		end
	end

	def test_transformer
		a = Rex::Transformer.transform([ 'yo', 'ho' ], Array, [ String ], 'Jones')

		assert_equal(2, a.length, "valid array length")
		assert_equal('yo', a[0], "valid first element")
		assert_equal('ho', a[1], "valid second element")

		assert_raise(Rex::ArgumentError, "invalid transform") {
			Rex::Transformer.transform('dog', Array, [ Pizza ], 'bob')
		}
	end
end
