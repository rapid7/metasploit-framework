#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/proto/smb/constants'
require 'rex/proto/smb/exceptions'
require 'rex/proto/smb/utils'
require 'rex/proto/smb/client'
require 'rex/proto/dcerpc'
require 'rex/socket'

class Rex::Proto::SMB::Client::UnitTest < Test::Unit::TestCase
	
	Klass = Rex::Proto::SMB::Client

	# Alias over the Rex DCERPC protocol modules
	DCERPCPacket   = Rex::Proto::DCERPC::Packet
	DCERPCClient   = Rex::Proto::DCERPC::Client
	DCERPCResponse = Rex::Proto::DCERPC::Response
	DCERPCUUID     = Rex::Proto::DCERPC::UUID
		
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
		
		ok = c.create('\\browser')
		assert_kind_of(Rex::Struct2::CStruct, ok)
		
		vers = DCERPCUUID.vers_by_name('SRVSVC')
		uuid = DCERPCUUID.uuid_by_name('SRVSVC')
		bind, ctx = DCERPCPacket.make_bind(uuid, vers)
		
		ok = c.trans_named_pipe(c.last_file_id, bind)
		assert_kind_of(Rex::Struct2::CStruct, ok)
		
		data = ok.to_s.slice(
			ok['Payload'].v['DataOffset'] + 4,
			ok['Payload'].v['DataCount']
		)
		
		head = data.slice!(0, 10)
		assert_equal(head.length, 10)
		
		resp = DCERPCResponse.new(head)
		resp.parse(data)
		
		assert_equal(resp.type, 12)
		
	end

	
end	
