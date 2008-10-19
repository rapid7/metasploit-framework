#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/exploitation/seh'

class Rex::Exploitation::Seh::UnitTest < Test::Unit::TestCase

	Klass = Rex::Exploitation::Seh

	def test_static_record
		r = Klass.new
		record = r.generate_static_seh_record(0x41414141)
		assert_equal("\xeb\x06", record[0, 2])
		assert_equal("\x41\x41\x41\x41", record[4, 4])
	end

end