##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'lib'))
$:.unshift(File.dirname(__FILE__))

require 'test/unit'
require 'rex/ui'
require 'msf/core'
require 'none'

class Metasploit3 < Msf::Test::Unit::TestCase

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
