#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'rex/test'
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
		
	def test_smb_open_share
		
		share = 'C$'
		
		write_data = ('A' * 256)
		filename = 'smb_test.txt'

		begin
		timeout($_REX_TEST_TIMEOUT) {
		s = Rex::Socket.create_tcp(
			'PeerHost' => $_REX_TEST_SMB_HOST,
			'PeerPort' => 139
		)

		c = Klass.new(s)
		
		# Request a SMB session over NetBIOS
		# puts "[*] Requesting a SMB session over NetBIOS..."
		ok = c.session_request()
		assert_kind_of(Rex::Struct2::CStruct, ok)
		
		# Check for a positive session response
		# A negative response is 0x83
		assert_equal(ok.v['Type'], 0x82)

		# puts "[*] Negotiating SMB dialects..."
		ok = c.negotiate()
		assert_kind_of(Rex::Struct2::CStruct, ok)

		# puts "[*] Authenticating with NTLMv2..."
		ok = c.session_setup_ntlmv2($_REX_TEXT_SMB_USER, $_REX_TEXT_SMB_PASS)
		assert_kind_of(Rex::Struct2::CStruct, ok)
		assert_not_equal(c.auth_user_id, 0)
		
		# puts "[*] Connecting to the share..."		
		ok = c.tree_connect(share)
		assert_kind_of(Rex::Struct2::CStruct, ok)
		assert_not_equal(c.last_tree_id, 0)
		
		# puts "[*] Opening a file for write..."
		ok = c.open(filename)
		assert_kind_of(Rex::Struct2::CStruct, ok)
		assert_not_equal(c.last_file_id, 0)
		
		# puts "[*] Writing data to the test file..."
		ok = c.write(c.last_file_id, 0, write_data)
		assert_kind_of(Rex::Struct2::CStruct, ok)
		assert_equal(ok['Payload'].v['CountLow'], write_data.length)
		
		# puts "[*] Closing the test file..."
		ok = c.close(c.last_file_id)
		assert_kind_of(Rex::Struct2::CStruct, ok)

		# puts "[*] Opening a file for read..."
		ok = c.open(filename, 1)
		assert_kind_of(Rex::Struct2::CStruct, ok)
		assert_not_equal(c.last_file_id, 0)	
		
		# puts "[*] Reading data from the test file..."
		ok = c.read(c.last_file_id, 0, write_data.length)
		assert_kind_of(Rex::Struct2::CStruct, ok)
		assert_equal(ok['Payload'].v['DataLenLow'], write_data.length)
		
		read_data =  ok.to_s.slice(
			ok['Payload'].v['DataOffset'] + 4,
			ok['Payload'].v['DataLenLow']
		)			
		assert_equal(read_data, write_data)

		# puts "[*] Closing the test file..."
		ok = c.close(c.last_file_id)
		assert_kind_of(Rex::Struct2::CStruct, ok)
		
		# puts "[*] Disconnecting from the tree..."	
		ok = c.tree_disconnect
		assert_kind_of(Rex::Struct2::CStruct, ok)
		
		s.close
		
		
		# Reconnect and delete the file
		s = Rex::Socket.create_tcp(
			'PeerHost' => $_REX_TEST_SMB_HOST,
			'PeerPort' => 139
		)

		c = Klass.new(s)
		
		# Request a SMB session over NetBIOS
		# puts "[*] Requesting a SMB session over NetBIOS..."
		ok = c.session_request()
		assert_kind_of(Rex::Struct2::CStruct, ok)
		
		# Check for a positive session response
		# A negative response is 0x83
		assert_equal(ok.v['Type'], 0x82)

		# puts "[*] Negotiating SMB dialects..."
		ok = c.negotiate()
		assert_kind_of(Rex::Struct2::CStruct, ok)

		# puts "[*] Authenticating with NTLMv2..."
		ok = c.session_setup_ntlmv2($_REX_TEXT_SMB_USER, $_REX_TEXT_SMB_PASS)
		assert_kind_of(Rex::Struct2::CStruct, ok)
		assert_not_equal(c.auth_user_id, 0)
		
		# puts "[*] Connecting to the share..."		
		ok = c.tree_connect(share)
		assert_kind_of(Rex::Struct2::CStruct, ok)
		assert_not_equal(c.last_tree_id, 0)
				
		# puts "[*] Deleting the test file..."
		ok = c.delete(filename)
		assert_kind_of(Rex::Struct2::CStruct, ok)
		
		# puts "[*] Diconnecting from the tree..."	
		ok = c.tree_disconnect
		assert_kind_of(Rex::Struct2::CStruct, ok)
		
		s.close	
		}
		rescue Timeout::Error
			flunk('timeout')
		end
		
	end

	def test_smb_session_request
		begin
		timeout($_REX_TEST_TIMEOUT) {
		s = Rex::Socket.create_tcp(
			'PeerHost' => $_REX_TEST_SMB_HOST,
			'PeerPort' => 139
		)

		c = Klass.new(s)
		
		# Request a SMB session over NetBIOS
		# puts "[*] Requesting a SMB session over NetBIOS..."
		ok = c.session_request()
		assert_kind_of(Rex::Struct2::CStruct, ok)
		
		# Check for a positive session response
		# A negative response is 0x83
		assert_equal(ok.v['Type'], 0x82)

		# puts "[*] Negotiating SMB dialects..."
		ok = c.negotiate()
		assert_kind_of(Rex::Struct2::CStruct, ok)

		# puts "[*] Authenticating with NTLMv2..."
		ok = c.session_setup_ntlmv2
		assert_kind_of(Rex::Struct2::CStruct, ok)
		
		# puts "[*] Authenticating with NTLMv1..."		
		ok = c.session_setup_ntlmv1
		assert_kind_of(Rex::Struct2::CStruct, ok)
		
		# puts "[*] Authenticating with clear text passwords..."
		begin		
			ok = c.session_setup_clear
			assert_kind_of(Rex::Struct2::CStruct, ok)
		rescue Rex::Proto::SMB::Exceptions::ErrorCode
			if ($!.error_code != 0x00010002)
				raise $!
			end
		end

		# puts "[*] Connecting to IPC$..."		
		ok = c.tree_connect
		assert_kind_of(Rex::Struct2::CStruct, ok)

		# puts "[*] Opening the \BROWSER pipe..."		
		ok = c.create_pipe('\BROWSER')
		assert_kind_of(Rex::Struct2::CStruct, ok)
		
		vers = DCERPCUUID.vers_by_name('SRVSVC')
		uuid = DCERPCUUID.uuid_by_name('SRVSVC')
		bind, ctx = DCERPCPacket.make_bind_fake_multi(uuid, vers)

		# puts "[*] Binding to the Server Service..."		
		ok = c.trans_named_pipe(c.last_file_id, bind)
		assert_kind_of(Rex::Struct2::CStruct, ok)
		
		data = ok.to_s.slice(
			ok['Payload'].v['DataOffset'] + 4,
			ok['Payload'].v['DataCount']
		)
		assert_not_equal(data, nil)
		
		resp = DCERPCResponse.new(data)
		assert_equal(resp.type, 12)
		}
		rescue Timeout::Error
			flunk('timeout')
		end
	end

	
end