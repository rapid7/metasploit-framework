#!/usr/bin/ruby

$:.unshift(File.join('..', File.dirname(__FILE__)))

require 'test/unit'
require 'Rex/Exceptions'

module Rex
module Exceptions

class UnitTest < Test::Unit::TestCase

	def test_exceptions
		Rex.constants.each { |const|
			mod = Rex.const_get(const)

			if ((mod.kind_of?(Class) == false) ||
			    (mod.ancestors.include?(Rex::Exception) == false))
				next
			end

			begin
				raise mod.new
			rescue mod => detail
				assert_respond_to(detail, 'to_s', "#{mod} does not implement to_s")
				assert_not_nil(detail.to_s, "invalid to_s")
			end
		}
	end

end

end
end
