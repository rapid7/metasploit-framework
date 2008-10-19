#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..'))

require 'test/unit'
require 'rex/exceptions'
require 'rex/transformer'

class Rex::Transformer::UnitTest < Test::Unit::TestCase
	class Pizza
		def Pizza.from_s(str)
		end
	end

	class ArrayTester
		def self.from_a(a)
			a[0] + a[1]
		end
	end

	def test_transformer
		a = Rex::Transformer.transform([ 'yo', 'ho' ], Array, [ String ], 'Jones')

		assert_equal(2, a.length, "invalid array length")
		assert_equal('yo', a[0], "invalid first element")
		assert_equal('ho', a[1], "invalid second element")

		assert_raise(Rex::ArgumentError, "invalid transform") {
			Rex::Transformer.transform('dog', Array, [ Pizza ], 'bob')
		}
	end

	def test_from_a
		a = Rex::Transformer.transform([ [ 'one', 'two' ] ], Array, [ ArrayTester ], 'Jimmy')

		assert_equal('onetwo', a[0], "invalid from_a conversion")
	end
end