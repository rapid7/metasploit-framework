#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..'))

require 'test/unit'
require 'rex/exceptions'

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
			rescue ::ArgumentError
			rescue mod => detail
				assert_respond_to(detail, 'to_s', "#{mod} does not implement to_s")
				assert_not_nil(detail.to_s, "invalid to_s")
			end
		}

		# Test communication error detail strings
		begin
			raise ConnectionRefused.new('127.0.0.1', 4444)
		rescue HostCommunicationError => detail
			assert_match(/^The connection(.*)\(127.0.0.1:4444\)/, detail.to_s)
			assert_equal('127.0.0.1', detail.host)
			assert_equal(4444, detail.port)
		end
	end

end

end
end