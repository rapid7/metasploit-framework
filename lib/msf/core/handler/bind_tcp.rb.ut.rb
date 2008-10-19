#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'msf/core'
require 'msf/core/handler/bind_tcp'

module Msf

class Handler::BindTcp::UnitTest < Test::Unit::TestCase

	class Stub < Msf::Payload
	end

	module Foo
		def handle_connection(client)
			self.success = 1
		end

		attr_accessor :success, :session
	end

	def test_handler
		c = Class.new(Stub)

		c.include(Foo, Msf::Handler::BindTcp)

		h = c.new({})

		begin
			t = Rex::Socket::TcpServer.create(
				'LocalPort' => 4444)

			h.datastore['RHOST'] = "127.0.0.1"
			h.datastore['LPORT'] = 4444

			h.start_handler

			Rex::ThreadSafe.sleep(1)

			assert_equal(1, h.success)
		ensure
			t.close if (t)
			h.stop_handler if (h)
		end
	end

end

end