#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/parser/ini'

class Rex::Parser::Ini::UnitTest < Test::Unit::TestCase

	Klass   = Rex::Parser::Ini
	TestIni = <<END
[group1]
cat=dog
bird=frog

[group2]
salad=cake
END

	def test_parse
		ini = Klass.from_s(TestIni)

		assert_equal('dog', ini['group1']['cat'])
		assert_equal('frog', ini['group1']['bird'])
		assert_equal('cake', ini['group2']['salad'])
		assert_equal(TestIni + "\n", ini.to_s)
	end
	
end