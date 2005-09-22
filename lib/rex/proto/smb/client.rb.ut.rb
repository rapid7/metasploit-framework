#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/proto/smb/constants'
require 'rex/proto/smb/utils'
require 'rex/proto/smb/client'
require 'rex/socket'

class Rex::Proto::SMB::Client::UnitTest < Test::Unit::TestCase
	
	Klass = Rex::Proto::SMB::Client

	@@host = '192.168.0.42'
	@@port = 139

	def test_smb_session_request

		s = Rex::Socket.create_tcp(
			'PeerHost' => @@host,
			'PeerPort' => @@port
		)

		c = Klass.new(s)
		
		# Request a SMB session over NetBIOS
		ok = c.session_request()
		assert_kind_of(Rex::Struct2::CStruct, ok)
		
		# Check for a positive session response
		# A negative response is 0x83
		assert_equal(ok.v['Type'], 0x82)


		# Negotiate a SMB dialect
		ok = c.negotiate()
		assert_kind_of(Rex::Struct2::CStruct, ok)


		ok = c.session_setup_ntlmv2
		assert_kind_of(Rex::Struct2::CStruct, ok)
		
		ok = c.session_setup_ntlmv1
		assert_kind_of(Rex::Struct2::CStruct, ok)
		
		ok = c.session_setup_clear
		assert_kind_of(Rex::Struct2::CStruct, ok)
		
		ok = c.tree_connect
		assert_kind_of(Rex::Struct2::CStruct, ok)
		
								
	end

	
end	
