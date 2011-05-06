#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/exploitation/egghunter'

class Rex::Exploitation::Egghunter::UnitTest < Test::Unit::TestCase

	Klass = Rex::Exploitation::Egghunter

	def test_egghunter
		payload = "\xcc" * 1023

		r = Klass.new('bogus')
		assert_nil(r.generate(payload))

		r = Klass.new('win')
		assert_nil(r.generate(payload))

		r = Klass.new('win', ARCH_X86)
		assert_not_nil(r.generate(payload))
		assert_not_nil(r.generate(payload)[0])
		assert_not_nil(r.generate(payload)[1])
	end

end