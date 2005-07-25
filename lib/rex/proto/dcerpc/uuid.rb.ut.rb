#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/proto/dcerpc/uuid'
	
class Rex::Proto::DCERPC::UUID::UnitTest < Test::Unit::TestCase

	Klass = Rex::Proto::DCERPC:UUID

	def test_parse
		d = Klass.new
		strA = '367abb81-9844-35f1-ad32-98f038001003'
		binA = d.uuid_pack(strA)
		strB = d.uuid_unpack(binA)
		binB = d.uuid_pack(strB)
		
		assert_equal(strA, strB)
		assert_equal(binA, binB)
		assert_true(d.uuid_by_name('MGMT'))
	end
end
