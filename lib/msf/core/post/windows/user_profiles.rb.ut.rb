#!/usr/bin/env ruby
# -*- coding: binary -*-

$:.unshift(File.join(File.dirname(__FILE__), '..','..','..','..','..', 'lib'))

require 'msf/core/post/windows/user_profiles'
require 'test/unit'

module Msf
class Post
module Windows
class UserProfiles::UnitTest < Test::Unit::TestCase

	def test_include
		assert_nothing_raised do
			Msf::Post.new.extend(Msf::Post::Windows::UserProfiles)
		end
	end

end
end
end
end
