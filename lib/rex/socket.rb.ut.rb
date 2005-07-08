#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..'))

require 'test/unit'
require 'Rex/Socket'
require 'Rex/Socket/Tcp'

class Rex::Socket::UnitTest < Test::Unit::TestCase

	def test_create
		serv = TCPServer.new('127.0.0.1', 65432)

		sock = nil
		assert_nothing_raised {
			sock = Rex::Socket.create(
				'PeerHost' => '127.0.0.1',
				'PeerPort' => 65432,
				'Proto'    => 'tcp')
		}
		assert_kind_of(Rex::Socket::Tcp, sock, "socket factory creation")

		sock = nil
		assert_nothing_raised {
			sock = Rex::Socket.create_tcp(
				'PeerHost' => '127.0.0.1',
				'PeerPort' => 65432)
		}
		assert_kind_of(Rex::Socket::Tcp, sock, "tcp socket factory creation")

		serv.close
	end

	def test_to_sockaddr
		assert_equal("\x00" * 16, Rex::Socket.to_sockaddr(nil, 0, 0), "null sockaddr")
		assert_equal("\x02\x00\x00\x16" + "\x00" * 12, Rex::Socket.to_sockaddr(nil, 22), "default addr, port 22 sockaddr")
		assert_equal("\x02\x00\x00\x16\x01\x02\x03\x04" + "\x00" * 8, Rex::Socket.to_sockaddr("1.2.3.4", 22), "1.2.3.4 addr, port 22 sockaddr")
	end

	def test_from_sockaddr
		af, host, port = Rex::Socket.from_sockaddr("\x00" * 16)
		assert_equal(0, af, "zero af")
		assert_equal('0.0.0.0', host, "zero host")
		assert_equal(0, port, "zero port")

		af, host, port = Rex::Socket.from_sockaddr("\x02\x00\x00\x16" + "\x00" * 12)
		assert_equal(2, af, "af = 2")
		assert_equal('0.0.0.0', host, "zero host")
		assert_equal(22, port, "port = 22")

		af, host, port = Rex::Socket.from_sockaddr("\x02\x00\x00\x16\x01\x02\x03\x04" + "\x00" * 8)
		assert_equal(2, af, "af = 2")
		assert_equal('1.2.3.4', host, "zero host")
		assert_equal(22, port, "port = 22")
	end

	def test_resolv_nbo
		assert_equal("\x04\x03\x02\x01", Rex::Socket.resolv_nbo("4.3.2.1"))
	end

end
