#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'rex/test'
require 'rex/proto/smb/crypt'

class Rex::Proto::SMB::Crypt::UnitTest < Test::Unit::TestCase
	
	Klass = Rex::Proto::SMB::Crypt

	def test_parse

		test_nt = "8d041858f078ccfa1560a4617690e55184fd70ec7f23b7f9"
		test_lm = "c248cf6165fe55efaca0300966dc3796046b9c0bb4a52e27"
		test_pass = "XXXXXXX"
		test_chal = "Z" * 8

		res_lm = Klass.lanman_des(test_pass, test_chal).unpack("H*")[0]
		res_nt = Klass.ntlm_md4(test_pass, test_chal).unpack("H*")[0]

		assert_equal(res_lm, test_lm)
		assert_equal(res_nt, test_nt)
	end
end	
