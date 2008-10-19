#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'msf/core/exceptions'

module Msf
module Exceptions

class UnitTest < Test::Unit::TestCase

	def test_exceptions
		Msf.constants.each { |const|
			mod = Msf.const_get(const)

			if ((mod.kind_of?(Class) == false) ||
			    (mod.ancestors.include?(Msf::Exception) == false))
				next
			end

			begin
				raise mod.new
			rescue mod => detail
				assert_respond_to(detail, 'to_s', "#{mod} does not implement to_s")
				assert_not_nil(detail.to_s, "invalid to_s")
			end
		}

		begin
			raise OptionValidateError.new([ 'test', 'best' ])
		rescue OptionValidateError => detail
			assert_match(/^The following/, detail.to_s)
		end
	end

end

end
end