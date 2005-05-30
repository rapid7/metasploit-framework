#!/usr/bin/ruby

$:.unshift(File.join('..', '..', '..', File.dirname(__FILE__)))

module Msf
module Module
end end

require 'test/unit'
require 'Msf/Core/Module/PlatformList'

class Msf::Module::PlatformList::UnitTest < Test::Unit::TestCase

	def test_range
		assert_equal(
		  [ Msf::Module::Platform::Windows::X86::XP::SP0,
		    Msf::Module::Platform::Windows::X86::XP::SP1
		  ], Msf::Module::PlatformList.new('winxpsp0' .. 'winxpsp1').platforms
		)
	end

	def test_names
		assert_equal([ 'Windows X86 XP SP2' ], Msf::Module::PlatformList.new('winxpsp2').names)
	end

	def test_all
		assert_equal( [ Msf::Module::Platform ], Msf::Module::PlatformList.new('').platforms)
	end

	def test_supports
		l1 = Msf::Module::PlatformList.new('win')
		l2 = Msf::Module::PlatformList.new('win xp sp0', 'win xp sp2')
		assert_equal( true, l1.supports?(l2) )
		assert_equal( false, l2.supports?(l1) )
	end
end
