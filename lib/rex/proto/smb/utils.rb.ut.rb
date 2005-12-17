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
	
	def test_unicode
		plain   = 'Metasploit!'
		unicode = "M\x00e\x00t\x00a\x00s\x00p\x00l\x00\o\x00i\x00t\x00!\x00" 
		
		assert_equal(Klass.unicode(plain), unicode)
	end
	
end	
