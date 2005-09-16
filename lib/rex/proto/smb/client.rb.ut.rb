#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/proto/smb/constants'
require 'rex/proto/smb/utils'
require 'rex/proto/smb/client'

class Rex::Proto::SMB::Client::UnitTest < Test::Unit::TestCase
	
	Klass = Rex::Proto::SMB::Client

	@@host = '192.168.0.2'
	@@port = 445

	def test_smb_session_request
		socket = 'Dummy'
		c = Klass.new(socket)
		c.session_request()
		
		# assert_equal(Klass.nbname_decode(nbencoded),  nbdecoded )
	end

	
end	
