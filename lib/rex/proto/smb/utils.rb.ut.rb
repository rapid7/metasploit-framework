#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'rex/test'
require 'rex/proto/smb/utils'

class Rex::Proto::SMB::Utils::UnitTest < Test::Unit::TestCase
	
	Klass = Rex::Proto::SMB::Utils

	def test_nbname
	
		nbdecoded = 'METASPLOITROCKS!'
		nbencoded = 'ENEFFEEBFDFAEMEPEJFEFCEPEDELFDCB'
		
		assert_equal(Klass.nbname_encode(nbdecoded),  nbencoded )
		assert_equal(Klass.nbname_decode(nbencoded),  nbdecoded )
	end
end