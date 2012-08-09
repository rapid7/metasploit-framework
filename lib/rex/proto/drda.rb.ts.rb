#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/test'

module Rex
	class Test
		$_REX_TEST_DRDA_HOST = "192.168.145.138"
		$_REX_TEST_DRDA_USER = "db2inst1"
		$_REX_TEST_DRDA_PASS = "db2pw"
	end
end

require 'rex/proto/drda/constants.rb.ut.rb'
require 'rex/proto/drda/packet.rb.ut.rb'
require 'rex/proto/drda/utils.rb.ut.rb'


