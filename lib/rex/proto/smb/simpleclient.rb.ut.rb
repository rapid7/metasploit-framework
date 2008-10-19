#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'rex/test'
require 'rex/proto/smb'
require 'rex/proto/dcerpc'
require 'rex/socket'

class Rex::Proto::SMB::SimpleClient::UnitTest < Test::Unit::TestCase
	
	Klass = Rex::Proto::SMB::SimpleClient

	# Alias over the Rex DCERPC protocol modules
	DCERPCPacket   = Rex::Proto::DCERPC::Packet
	DCERPCClient   = Rex::Proto::DCERPC::Client
	DCERPCResponse = Rex::Proto::DCERPC::Response
	DCERPCUUID     = Rex::Proto::DCERPC::UUID
	XCEPT          = Rex::Proto::SMB::Exceptions
	
	FILE_CREATE = 0x10
	FILE_TRUNC  = 0x02
	FILE_OPEN   = 0x01
	
	
	def test_smb_open_share
		user = 'SMBTest'
		pass = 'SMBTest'
		share = 'C$'
		
		write_data = ('A' * (1024 * 8))
		filename = 'smb_tester.txt'
		begin
		timeout($_REX_TEST_TIMEOUT) {
		s = Rex::Socket.create_tcp(
			'PeerHost' => $_REX_TEST_SMB_HOST,
			'PeerPort' => 445
		)

		c = Klass.new(s, true)
		
		begin
	        c.login('*SMBSERVER', user, pass)
		rescue XCEPT::LoginError
			flunk('login failure')
		end

		c.connect(share)
			
		f = c.open(filename, 'rwct')
	    f << write_data
		f.close
			
		f = c.open(filename, 'ro')
	    d = f.read()
	    f.close
			
		c.delete(filename)
		c.disconnect(share)

		s.close	
		}
		rescue Timeout::Error
			flunk('timeout')
		end
	end

	def test_smb_dcerpc
		begin
		timeout($_REX_TEST_TIMEOUT) {
		s = Rex::Socket.create_tcp(
			'PeerHost' => $_REX_TEST_SMB_HOST,
			'PeerPort' => 445
		)

		c = Klass.new(s, true)

		user = ''
		pass = ''

		begin
			c.login('*SMBSERVER', user, pass)
		rescue XCEPT::LoginError
			flunk('login failure')
		end

		c.connect('IPC$')
		f = c.create_pipe('\BROWSER')
			
		bind, ctx = DCERPCPacket.make_bind_fake_multi(
			'4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0',
			10, 
			4
		)
			
		# Evasion techniques:
		# 	1) Write the bind out a few bytes at a time with a random offset
		#	2) Read the response back a few bytes at a time with a random offset

		# Write the bind request out in random chunk sizes
		while (bind.length > 0)
		    f.write( bind.slice!(0, (rand(20)+5)), rand(1024)+1 )
		end
			
		d = ''
		# Read the response back a few bytes a time
		begin
		    while(true)
			    t = (f.read((rand(20)+5), rand(1024)+1))
				last if ! t.length
				d << t
			end
		rescue XCEPT::NoReply
		end

		r = DCERPCResponse.new(d)
		assert_equal(r.type, 12)
		assert_equal(r.ack_result[ctx-0], 0)
		assert_equal(r.ack_result[ctx-1], 2)

		s.close	
		}
		rescue Timeout::Error
			flunk('timeout')
		end
	end
end