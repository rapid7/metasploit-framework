#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/proto/smb'
require 'rex/proto/dcerpc'
require 'rex/socket'

class Rex::Proto::SMB::Client::UnitTest < Test::Unit::TestCase
	
	Klass = Rex::Proto::SMB::SimpleClient

	# Alias over the Rex DCERPC protocol modules
	DCERPCPacket   = Rex::Proto::DCERPC::Packet
	DCERPCClient   = Rex::Proto::DCERPC::Client
	DCERPCResponse = Rex::Proto::DCERPC::Response
	DCERPCUUID     = Rex::Proto::DCERPC::UUID
	
	FILE_CREATE = 0x10
	FILE_TRUNC  = 0x02
	FILE_OPEN   = 0x01
	
	
	@@host = '192.168.0.219'
	@@port = 445

	def test_smb_open_share
		
		user = 'SMBTest'
		pass = 'SMBTest'
		share = 'C$'
		
		write_data = ('A' * (1024 * 1024 * 1))
		filename = 'smb_tester.txt'
		
		s = Rex::Socket.create_tcp(
			'PeerHost' => @@host,
			'PeerPort' => @@port
		)

		c = Klass.new(s, true)
		
		begin
			c.login('*SMBSERVER', user, pass)
			c.connect(share)
			
			f = c.open(filename, FILE_CREATE|FILE_TRUNC)
			f << write_data
			f.close
			
			f = c.open(filename, FILE_OPEN)
			d = f.read()
			f.close
			
			c.delete(filename)
			c.disconnect(share)
			assert_equal(write_data, d)
		rescue
			puts $!.to_s + $!.backtrace.join("\n")
			return
		end

		s.close	
		
	end

	
end	
