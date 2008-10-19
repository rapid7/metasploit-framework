#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'msf/core'

module Msf

class Module::Author::UnitTest < Test::Unit::TestCase
	def test_known
		assert_match(/^skape /, Author.from_s('skape').to_s)
		assert_equal('skape <mmiller@hick.org>', Author.from_s('skape').to_s)
	end

	def test_raw
		assert_equal('skapino', Author.from_s('skapino <johnson@jones.com>').name)
		assert_equal('johnson@jones.com', Author.from_s('skapino <johnson@jones.com>').email)
		assert_equal('skapino <johnson@jones.com>', Author.from_s('skapino <johnson@jones.com>').to_s)
	end
end

end