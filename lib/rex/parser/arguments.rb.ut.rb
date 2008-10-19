#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/parser/arguments'

class Rex::Parser::Arguments::UnitTest < Test::Unit::TestCase

	def test_parse
		args =
			[
				"-b",
				"foo",
				"-c",
				"-f",
				"-g",
				"arg",
				"none"
			]

		b = nil
		c = false
		f = false
		g = nil
		none = nil

		Rex::Parser::Arguments.new(
			'-b' => [ true,  "bee" ],
			'-c' => [ false, "cee" ],
			'-f' => [ false, "eff" ],
			'-g' => [ true,  "gee" ]).parse(args) { |opt, idx, val|
			case opt
				when nil
					none = val
				when '-b'
					b = val
				when '-c'
					c = true
				when '-f'
					f = true
				when '-g'
					g = val
			end
		}

		assert_equal(b, "foo")
		assert_equal(c, true)
		assert_equal(f, true)
		assert_equal(g, "arg")
		assert_equal(none, "none")
	end

	def test_from_s
		args = Rex::Parser::Arguments.from_s(
			"this is a test \"of the emergency pimping\" system \\\"buh lee dat\\\" yup")

		assert_equal(args[0], "this")
		assert_equal(args[3], "test")
		assert_equal(args[4], "of the emergency pimping")
		assert_equal(args[5], "system")
		assert_equal(args[6], "\"buh")
		assert_equal(args[8], "dat\"")
		assert_equal(args[9], "yup")
	end

end