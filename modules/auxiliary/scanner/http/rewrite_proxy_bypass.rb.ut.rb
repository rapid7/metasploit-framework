#!/usr/bin/env ruby

project_root = File.join(File.dirname(__FILE__), '..', '..', '..', '..')
$:.unshift(File.join(project_root, 'lib'))
$:.unshift(File.join(project_root, 'modules'))

require 'test/unit'
require 'msf/core'

class RewriteProxyBypassUnitTest < Test::Unit::TestCase

	def test_require
		assert_nothing_raised do
			require 'auxiliary/scanner/http/rewrite_proxy_bypass'
		end
	end

end
