#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'rex/test'
require 'rex/proto/smb/constants'

class Rex::Proto::SMB::Constants::UnitTest < Test::Unit::TestCase
	
	Klass = Rex::Proto::SMB::Constants

	def test_defines
		assert_equal(Klass::SMB_COM_CREATE_DIRECTORY,  0x00 )
		assert_equal(Klass::SMB_COM_NT_CREATE_ANDX, 0xa2 )
		assert_equal(Klass::NT_TRANSACT_QUERY_SECURITY_DESC, 0x06)
	end
	
end