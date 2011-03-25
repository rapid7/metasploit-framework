#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..','..','..','..','..', 'lib')) 

require 'rex/post/meterpreter/extensions/stdapi/railgun/buffer_item'
require 'test/unit'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
class BufferItem::UnitTest < Test::Unit::TestCase

	def test_initialization
		target_belongs_to_param_n = 1
		target_addr = 232323
		target_length_in_bytes = 4
		target_datatype = "DWORD"
	
		item = BufferItem.new(target_belongs_to_param_n, target_addr, 
					target_length_in_bytes, target_datatype)

		assert_equal(target_belongs_to_param_n, item.belongs_to_param_n)
		assert_equal(target_addr, item.addr)
		assert_equal(target_length_in_bytes, item.length_in_bytes)
		assert_equal(target_datatype, item.datatype)
	end
end
end
end
end
end
end
end
