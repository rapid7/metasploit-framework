#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..','..','..','..','..', 'lib')) 

require 'rex/post/meterpreter/extensions/stdapi/railgun/win_const_manager'
require 'test/unit'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
class WinConstManager::UnitTest < Test::Unit::TestCase
	def test_is_parseable
		const_manager = WinConstManager.new

		first_key = 'SOME_NUMBER'
		second_key = 'SOME_OTHER_NUMBER'
		boolean_logic = first_key + ' | ' + second_key

		# XXX: Should check (un)parseability before adding constants too?

		const_manager.add_const(first_key, 43123)
		const_manager.add_const(second_key, 234)

		assert(const_manager.is_parseable(boolean_logic),
			"is_parseable should consider boolean logic statements parseable")

		assert(const_manager.is_parseable(first_key),
			"is_parseable should consider constants parseable")

		assert(! const_manager.is_parseable(5),
			"is_parseable should not consider non-string keys as parseable")

		assert(! const_manager.is_parseable('| FOO |'),
			"is_parseable should not consider malformed boolean expressions parseable")
	end

	def test_add_const
		target_key = 'VALID_KEY'
		target_value = 23
		
		const_manager = WinConstManager.new

		const_manager.add_const(target_key, target_value)

		assert_equal(target_value, const_manager.parse(target_key),
			"add_const should add a constant/value pair that can be trieved with parse")
		
	end

	def test_initialization
		target_key = 'VALID_KEY'
		target_value = 23

		const_manager = WinConstManager.new(target_key => target_value)

		assert_equal(target_value, const_manager.parse(target_key),
			"upon initialization, should add any provided constants.")
	end

	def test_parse
		target_key = 'VALID_KEY'
		target_value = 23
		invalid_key = 8

		const_manager = WinConstManager.new

		const_manager.add_const(target_key, target_value)

		assert_equal(target_value, const_manager.parse(target_key),
			"parse should retrieve the corresponding value when a key is provided")

		# From API: "should not throw an exception given an invalid key"
		assert_nothing_thrown do 
			const_manager.parse(invalid_key)
		end

		assert_equal(nil, const_manager.parse(invalid_key),
			"parse should return nil when an invalid key is provided")

		x_key = 'X'
		x_value = 228
		y_key = 'Y'
		y_value = 15 

		boolean_logic = x_key + ' | ' + y_key
		target_boolean_logic_result = x_value | y_value

		const_manager.add_const(x_key, x_value)
		const_manager.add_const(y_key, y_value)

		assert_equal(target_boolean_logic_result, const_manager.parse(boolean_logic),
			"parse should evaluate boolean expressions consisting of OR")
	end
end
end
end
end
end
end
end
