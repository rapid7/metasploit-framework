#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'lib'))
$:.unshift(File.dirname(__FILE__))

require 'test/unit'
require 'rex/ui'
require 'msf/core'
require 'none'

class Msf::Encoders::Generic::None::UnitTest < Test::Unit::TestCase

	Klass = Msf::Encoders::Generic::None

	def test_encoder

		k = Klass.new

		[
			"\x41\x42\x43\x44",
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		].each { |raw|
			assert_equal(
				raw, k.encode(raw, '')
			)
		}
		
	end

end
