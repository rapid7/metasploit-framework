#!/usr/bin/env ruby
# -*- coding: binary -*-

$:.unshift(File.join(File.dirname(__FILE__), '..','..','..','..','..', '..', '..', 'lib'))

require 'rex/post/meterpreter/extensions/stdapi/railgun/platform_util'
require 'rex/post/meterpreter/extensions/stdapi/railgun/mock_magic'
require 'test/unit'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
class PlatformUtil::UnitTest < Test::Unit::TestCase
	def test_parse_client_platform
		assert_equal(PlatformUtil.parse_client_platform('x86/win32'), PlatformUtil::X86_32,
			'parse_client_platform should translate Win32 client platforms')
		assert_equal(PlatformUtil.parse_client_platform('x86/win64'), PlatformUtil::X86_64,
			'parse_client_platform should translate Win64 client platforms')
	end
end
end
end
end
end
end
end
