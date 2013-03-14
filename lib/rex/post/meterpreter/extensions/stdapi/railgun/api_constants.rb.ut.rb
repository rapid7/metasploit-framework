#!/usr/bin/env ruby
# -*- coding: binary -*-

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..','..','..','..'))

require 'rex/post/meterpreter/extensions/stdapi/railgun/api_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/win_const_manager'
require 'rex/text'
require 'test/unit'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
class ApiConstants::UnitTest < Test::Unit::TestCase
	def test_manager
		const_manager = ApiConstants.manager

		assert_equal(0, const_manager.parse('SUCCESS'),
			"ApiConstants.manager should return a functional constant manager for WinAPI constants")
	end

	def test_add_constants
		const_manager = WinConstManager.new

		ApiConstants.add_constants(const_manager)

		assert_equal(0, const_manager.parse('SUCCESS'),
			"ApiConstants.add_constants should have added WinAPI constants to given constant manager")
	end
end
end
end
end
end
end
end
