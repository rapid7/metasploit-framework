#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'msf/core'
require 'msf/core/handler/reverse_tcp'

module Msf

class Handler::ReverseTcp::UnitTest < Test::Unit::TestCase

	class Stub < Msf::Payload
		include Msf::Handler::ReverseTcp
	end

	module Foo
		def handle_connection(client)
			self.success = 1
		end

		attr_accessor :success, :session
	end

	def test_handler
		c = Class.new(Stub)
		c.include(Foo)

		h = c.new({})

		begin
			h.datastore['LPORT'] = 4444

			h.setup_handler
			h.start_handler

			5.times {
				t = Rex::Socket::Tcp.create(
					'PeerHost' => "127.0.0.1",
					'PeerPort' => 4444)

				assert_not_nil(t)

				begin
					Rex::ThreadSafe.sleep(1)
	
					assert_equal(1, h.success)
	
					h.success = 0
				ensure
					t.close
				end
			}
		ensure
			h.stop_handler if (h)
			h.cleanup_handler if (h)
		end
	end

end

end