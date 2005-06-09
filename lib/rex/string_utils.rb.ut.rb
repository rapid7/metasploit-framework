#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..'))

require 'test/unit'
require 'Rex/StringUtils'

class Rex::StringUtils::UnitTest < ::Test::Unit::TestCase
	Klass = Rex::StringUtils
	def klass
		self.class::Klass
	end

	def test_badchar_index
		assert_equal(nil, klass.badchar_index('abcdef', 'gzk'))
		assert_equal(2, klass.badchar_index('123avd', 'ly3'))
	end
		
end
