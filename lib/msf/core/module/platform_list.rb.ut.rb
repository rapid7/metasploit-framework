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
		  ], Msf::Module::PlatformList.new('winxpsp0' .. 'winxpsp1').modules
		)
	end

	def test_names
		assert_equal([ 'Windows X86 XP SP2' ], Msf::Module::PlatformList.new('winxpsp2').names)
	end

	def test_all
		assert_equal( [ Msf::Module::Platform ], Msf::Module::PlatformList.new('').modules)
	end
end
