#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/exploitation/egghunter'

class Rex::Exploitation::Egghunter::UnitTest < Test::Unit::TestCase

	Klass = Rex::Exploitation::Egghunter

	def test_egghunter
		r = Klass.new('bogus')
		assert_nil(r.generate)

		r = Klass.new('win')
		assert_nil(r.generate)

		r = Klass.new('win', ARCH_X86)
		assert_not_nil(r.generate)
		assert_not_nil(r.generate[0])
		assert_not_nil(r.generate[1])
	end

end