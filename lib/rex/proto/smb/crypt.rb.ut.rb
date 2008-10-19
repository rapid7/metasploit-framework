#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'rex/test'
require 'rex/proto/smb/crypt'

class Rex::Proto::SMB::Crypt::UnitTest < Test::Unit::TestCase
	
	Klass = Rex::Proto::SMB::Crypt

	def test_parse

		pass = "XXXXXXX"
		chal = "Z" * 8

		assert_equal("\xc2\x48\xcf\x61\x65\xfe\x55\xef\xac\xa0\x30\x09\x66\xdc\x37\x96\x04\x6b\x9c\x0b\xb4\xa5\x2e\x27", Klass.lanman_des(pass, chal), 'lanman_des')
		assert_equal("\x8d\x04\x18\x58\xf0\x78\xcc\xfa\x15\x60\xa4\x61\x76\x90\xe5\x51\x84\xfd\x70\xec\x7f\x23\xb7\xf9", Klass.ntlm_md4(pass, chal), 'ntlm_md4')
	end
end