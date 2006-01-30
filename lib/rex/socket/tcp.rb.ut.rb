#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/socket/tcp'

class Rex::Socket::Tcp::UnitTest < Test::Unit::TestCase

	def test_tcp
		serv_port = 65433
		serv = TCPServer.new('127.0.0.1', serv_port)
		t = nil

		begin
			# Connect to the temp server
			assert_nothing_raised {
				t = Rex::Socket.create_tcp(
					'PeerHost' => '127.0.0.1',
					'PeerPort' => serv_port)
			}
			assert_kind_of(Rex::Socket::Tcp, t, "valid tcp socket")
			assert_equal('127.0.0.1', t.peerhost, "matching peerhost")
			assert_equal(serv_port, t.peerport, "matching peerport")

			# Accept the client connection
			serv_con = serv.accept
			assert_kind_of(TCPSocket, serv_con, "valid server socket connection")

			assert_equal(5, t.write("test\n"), "cli: write test")
			assert_equal("test\n", serv_con.recv(5), "srv: read test")
			assert_equal(10, serv_con.send("A" * 10, 10), "srv: write A*10")
			assert_equal("A" * 10, t.get, "cli: gobble A*10")
			assert_equal(5, t << "test\n", "cli: << test")
			assert_equal("test\n", serv_con.recv(5), "srv: read test (2)")
			assert_equal(5, serv_con.send("testa", 6), "srv: write testa (3)")
			assert_equal(true, t.has_read_data?(1), "cli: poll read")
			assert_equal("testa", t.get, "cli: gobble testa")
			assert_equal(true, t.shutdown(::Socket::SHUT_RD), "cli: shutdown read")
			assert_equal(true, t.shutdown(::Socket::SHUT_WR), "cli: shutdown read")
			assert_nothing_raised {
				t.close
				t = nil
			}
		ensure
			t.close if (t)
			serv.close
		end
	end

end
