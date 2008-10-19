#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..'))

require 'test/unit'
require 'rex/socket'
require 'rex/socket/tcp'

class Rex::Socket::UnitTest < Test::Unit::TestCase

	def test_ip
		assert_equal(true,Rex::Socket.dotted_ip?('0.0.0.0'), 'valid IP min')
		assert_equal(true,Rex::Socket.dotted_ip?('255.255.255.255'), 'valid IP max')
		assert_equal(false,Rex::Socket.dotted_ip?('0.0.0.0.0'), 'too many sections')
		assert_equal(false,Rex::Socket.dotted_ip?('0..0.0.0'), 'too many dots')
		assert_equal(false,Rex::Socket.dotted_ip?('00.0.0'), 'not enough dots')
		assert_equal(false,Rex::Socket.dotted_ip?('256.256.256.256'), 'numbers too big')
	end

	def test_create
		port = 64442
		serv = TCPServer.new('127.0.0.1', port)

		sock = nil
		assert_nothing_raised {
			sock = Rex::Socket.create(
				'PeerHost' => '127.0.0.1',
				'PeerPort' => port,
				'Proto'    => 'tcp')
		}
		assert_kind_of(Rex::Socket::Tcp, sock, "socket factory creation")

		sock = nil
		assert_nothing_raised {
			sock = Rex::Socket.create_tcp(
				'PeerHost' => '127.0.0.1',
				'PeerPort' => port)
		}
		assert_kind_of(Rex::Socket::Tcp, sock, "tcp socket factory creation")

		serv.close
	end

	def test_to_sockaddr
		assert_equal("\x00" * 16, Rex::Socket.to_sockaddr(nil, 0, 0), "null sockaddr")
		assert_equal([2].pack('s') + "\x00\x16" + "\x00" * 12, Rex::Socket.to_sockaddr(nil, 22), "default addr, port 22 sockaddr")
		assert_equal([2].pack('s') + "\x00\x16\x01\x02\x03\x04" + "\x00" * 8, Rex::Socket.to_sockaddr("1.2.3.4", 22), "1.2.3.4 addr, port 22 sockaddr")
	end

	def test_from_sockaddr
		af, host, port = Rex::Socket.from_sockaddr("\x00" * 16)
		assert_equal(0, af, "zero af")
		assert_equal('0.0.0.0', host, "zero host")
		assert_equal(0, port, "zero port")

		af, host, port = Rex::Socket.from_sockaddr([2].pack('s') + "\x00\x16" + "\x00" * 12)
		assert_equal(2, af, "af = 2")
		assert_equal('0.0.0.0', host, "zero host")
		assert_equal(22, port, "port = 22")

		af, host, port = Rex::Socket.from_sockaddr([2].pack('s') + "\x00\x16\x01\x02\x03\x04" + "\x00" * 8)
		assert_equal(2, af, "af = 2")
		assert_equal('1.2.3.4', host, "zero host")
		assert_equal(22, port, "port = 22")
	end

	def test_resolv_nbo
		assert_equal("\x04\x03\x02\x01", Rex::Socket.resolv_nbo("4.3.2.1"))
	end

	def test_net2bitmask
		assert_equal(32, Rex::Socket.net2bitmask('255.255.255.255'))
		assert_equal(28, Rex::Socket.net2bitmask('255.255.255.240'))
		assert_equal(24, Rex::Socket.net2bitmask('255.255.255.0'))
		assert_equal(16, Rex::Socket.net2bitmask('255.255.0.0'))
	end

	def test_bit2netmask
		assert_equal("255.255.255.255", Rex::Socket.bit2netmask(32))
		assert_equal("255.255.255.254", Rex::Socket.bit2netmask(31))
		assert_equal("255.255.255.240", Rex::Socket.bit2netmask(28))
		assert_equal("255.255.255.0", Rex::Socket.bit2netmask(24))
		assert_equal("255.255.0.0", Rex::Socket.bit2netmask(16))
	end

end