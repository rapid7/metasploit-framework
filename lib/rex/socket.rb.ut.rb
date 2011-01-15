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
		assert_equal(([2] + [0]*14).pack("sC*"), Rex::Socket.to_sockaddr(0, 0), "null sockaddr")
=begin
# This is platform dependent, pain to test
		if (Rex::Socket.support_ipv6?)
			# Use the constant for AF_INET6 since it is different per platform
			# (10 on linux and 28 on BSD)
			inaddr_any_sockaddr = ([::Socket::AF_INET6, 22] + [0]*24).pack('sSC*')
		else
			inaddr_any_sockaddr = ([2, 22] + [0]*12).pack('snC*')
		end
=end
		assert_equal(([2, 0x16, 1, 2, 3, 4] + [0]*8).pack('snC*'), Rex::Socket.to_sockaddr("1.2.3.4", 22), "1.2.3.4 addr, port 22 sockaddr")
	end

	def test_from_sockaddr
		# 1.9.1 raises ArgumentError if we don't have an af == AF_INET or AF_INET6
		af, host, port = Rex::Socket.from_sockaddr(([2, 0] + [0]*12).pack('snC*'))
		assert_equal(2, af, "af = 2")
		assert_equal('0.0.0.0', host, "zero host")
		assert_equal(0, port, "zero port")

		af, host, port = Rex::Socket.from_sockaddr(([2, 22]+[0]*12).pack('snC*'))
		assert_equal(2, af, "af = 2")
		assert_equal(22, port, "port = 22")
		assert_equal('0.0.0.0', host, "zero host")

		af, host, port = Rex::Socket.from_sockaddr(([2, 22, 1, 2, 3, 4] + [0]*8).pack('snC*') )
		assert_equal(2, af, "af = 2")
		assert_equal('1.2.3.4', host, "host = '1.2.3.4'")
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

	def test_is_internal
		assert( ! Rex::Socket.is_internal?("1.2.3.4"))
		assert( ! Rex::Socket.is_internal?("172.15.3.4"))
		assert( ! Rex::Socket.is_internal?("172.32.3.4"))
		assert(Rex::Socket.is_internal?("10.2.3.4"))
		assert(Rex::Socket.is_internal?("192.168.3.4"))
		16.upto(31) do |octet|
			assert(Rex::Socket.is_internal?("172.#{octet}.3.4"))
		end
	end

end
