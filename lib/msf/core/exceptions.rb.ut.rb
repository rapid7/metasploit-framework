#!/usr/bin/ruby

$:.unshift(File.join('..', '..', File.dirname(__FILE__)))

require 'test/unit'
require 'Msf/Core/Exceptions'

module Msf
module Exceptions

class UnitTest < Test::Unit::TestCase

	def test_exceptions
		
		begin
			raise OptionValidateError.new([ 'test', 'best' ])
		rescue OptionValidateError => detail
			assert_match(/^The following/, detail.to_s)
		end

	end

end

end
end
