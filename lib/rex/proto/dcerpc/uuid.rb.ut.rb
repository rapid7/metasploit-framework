#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'rex/test'
require 'rex/exceptions'
require 'rex/proto/dcerpc/uuid'

class Rex::Proto::DCERPC::UUID::UnitTest < Test::Unit::TestCase

	Klass = Rex::Proto::DCERPC::UUID

	def test_is_uuid
		assert(Klass.is?('afa8bd80-7d8a-11c9-bef4-08002b102989'), 'valid')
		assert(!Klass.is?('afa8bd80-7d8a-11c9-bef4-08002b10298'), 'too short')
		assert(!Klass.is?('afa8bd80-7d8a-11c9-bef4-08002b10298Z'), 'invalid character')
		assert(!Klass.is?('afa8bd80-7d8a-11c9-bef4a08002b10298a'), 'missing dash')
		assert(!Klass.is?('afa8bd80-7d8a-11c9-bef-a08002b10298a'), 'dash in wrong place')
		assert_raise(Rex::ArgumentError, 'pack - too short') { Klass.is?(nil) }
	end

	def test_lookup
		assert_equal(Klass.uuid_by_name('MGMT'), 'afa8bd80-7d8a-11c9-bef4-08002b102989', 'uuid_by_name')
		assert_equal(Klass.vers_by_name('MGMT'), '2.0', 'vers_by_name')
		assert(!Klass.uuid_by_name('NO_SUCH_UUID'), 'uuid_by_name - invalid')
		assert(!Klass.vers_by_name('NO_SUCH_UUID'), 'vers_by_name - invalid')
	end

	def test_packing
		uuid = '367abb81-9844-35f1-ad32-98f038001003'
		assert_equal(Klass.uuid_pack(uuid), "\201\273z6D\230\3615\2552\230\3608\000\020\003", 'pack')
		assert_equal(Klass.uuid_unpack("\201\273z6D\230\3615\2552\230\3608\000\020\003"), uuid, 'unpack')
		assert_raise(Rex::ArgumentError, 'pack - too short') { Klass.uuid_pack('foo') }
		assert_raise(Rex::ArgumentError, 'unpack - too short') { Klass.uuid_unpack('foo') }
	end

	def test_xfer
		assert_equal(Klass.xfer_syntax_uuid(), "\004]\210\212\353\034\311\021\237\350\010\000+\020H`", 'xfer_syntax_uuid')
		assert_equal(Klass.xfer_syntax_vers(), '2.0', 'xfer_syntax_vers')
	end

	def test_vers
		assert_equal(Klass.vers_to_nums('2.0'), [2, 0], 'vers_to_nums')
		assert_equal(Klass.vers_to_nums('2'), [2, 0], 'vers_to_nums (short)')
	end
end