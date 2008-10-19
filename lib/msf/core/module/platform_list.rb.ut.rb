#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'msf/core'
require 'msf/core/module/platform_list'

class Msf::Module::PlatformList::UnitTest < Test::Unit::TestCase

	def test_range
		assert_equal(
		  [ Msf::Module::Platform::Windows::XP::SP0,
		    Msf::Module::Platform::Windows::XP::SP1
		  ], Msf::Module::PlatformList.new('winxpsp0' .. 'winxpsp1').platforms
		)
	end

	def test_names
		assert_equal([ 'Windows XP SP2' ], Msf::Module::PlatformList.new('winxpsp2').names)
	end

	def test_transform
		assert_equal([ 'Windows XP SP2' ], Msf::Module::PlatformList.transform('winxpsp2').names)
		assert_equal([ 'Windows XP SP2' ], Msf::Module::PlatformList.transform(['winxpsp2']).names)
		assert_equal([ 'Windows 2000 SP3' ], Msf::Module::PlatformList.transform(['win2000sp3']).names)
		assert_equal([ 'Windows 2000 SP3' ], Msf::Module::PlatformList.transform(['win2ksp3']).names)
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

	def test_intersect
		l1 = Msf::Module::PlatformList.new('win')
		l2 = Msf::Module::PlatformList.new('win xp sp0', 'win xp sp2')
		assert_equal(
		  [ Msf::Module::Platform::Windows::XP::SP0,
		    Msf::Module::Platform::Windows::XP::SP2
		  ], (l1 & l2).platforms
		)

		l1 = Msf::Module::PlatformList.new('win xp sp1')
		assert_equal( [ ], (l1 & l2).platforms )
	end
end