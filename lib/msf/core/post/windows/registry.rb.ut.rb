#!/usr/bin/env ruby
# -*- coding: binary -*-

$:.unshift(File.join(File.dirname(__FILE__), '..','..','..','..','..', 'lib'))

require 'msf/core/post/windows/registry'
require 'test/unit'

module Msf
class Post
module Windows
class Registry::UnitTest < Test::Unit::TestCase

	def test_include
		assert_nothing_raised do
			Msf::Post.new.extend(Msf::Post::Windows::Registry)
		end
	end

end
end
end
end
