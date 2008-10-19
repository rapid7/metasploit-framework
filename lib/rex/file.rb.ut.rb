#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..'))

require 'test/unit'
require 'rex/file'

class Rex::FileUtils::UnitTest < ::Test::Unit::TestCase
	Klass = Rex::FileUtils

	def test_find_full_path
		assert_not_nil(Klass.find_full_path("ls"))
		assert_nil(Klass.find_full_path("cookie monster cake"))
	end
		
end