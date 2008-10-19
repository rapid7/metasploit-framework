#!/usr/bin/env ruby -I../lib

$:.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'test/unit'

require 'encoders/generic/none.rb.ut'
require 'encoders/x86/call4_dword_xor.rb.ut'
require 'encoders/x86/countdown.rb.ut'
require 'encoders/x86/fnstenv_mov.rb.ut'
require 'encoders/x86/jmp_call_additive.rb.ut'

class Rex::TestSuite
	def self.suite
		suite = Test::Unit::TestSuite.new("Rex")

		# General
		suite << Msf::Encoders::Generic::None::UnitTest.suite
		suite << Msf::Encoders::X86::Call4Dword::UnitTest.suite
		suite << Msf::Encoders::X86::Countdown::UnitTest.suite
		suite << Msf::Encoders::X86::FnstenvMov::UnitTest.suite
		suite << Msf::Encoders::X86::JmpCallAdditive::UnitTest.suite

		return suite;
	end
end