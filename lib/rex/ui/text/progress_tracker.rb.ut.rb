#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/ui'

class Rex::Ui::Text::ProgressTracker::UnitTest < Test::Unit::TestCase

	def test_stuff
		output   = Rex::Ui::Text::Output::Buffer.new
		pt       = Rex::Ui::Text::ProgressTracker.new(output)

		pt.range = 1..10
	
		assert_equal(1, pt.start)
		assert_equal(10, pt.stop)

		pt.start = 2
		assert_equal(2, pt.start)
		pt.stop = 9
		assert_equal(9, pt.stop)
		assert_equal(2, pt.pos)
		assert_equal('', output.buf)
		assert_equal(3, pt.step)
		assert_equal(4, pt.step("test"))
		assert_equal("[*] 4: test\n", output.buf)
		output.reset
		assert_equal("[-] bad\n", pt.error("bad"))
		output.reset
		assert_equal("[-] fatal: bad\n", pt.abort("bad"))
	end

end