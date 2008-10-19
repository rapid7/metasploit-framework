#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/socket/udp'

class Rex::Socket::Udp::UnitTest < Test::Unit::TestCase

	def test_udp
		serv_port = 55432
		serv = Rex::Socket::Udp.create(
			'LocalHost' => '127.0.0.1',
			'LocalPort' => serv_port)

		begin
			assert_kind_of(Rex::Socket::Udp, serv, "valid Udp server instance")

			# Test connected socket
			concli = Rex::Socket::Udp.create(
				'PeerHost' => '127.0.0.1',
				'PeerPort' => serv_port)

			assert_equal('127.0.0.1', concli.peerhost, "matching peerhost")
			assert_equal(serv_port, concli.peerport, "matching peerport")
			assert_equal(2, concli.write('yo'), "write succeeded")

			data, host, port = serv.recvfrom

			assert_equal('yo', data, "read data match")
			assert_equal('127.0.0.1', host, "matching client host")

			# Test non-connected socket
			concli = Rex::Socket::Udp.create

			assert_equal(3, concli.sendto('bob', '127.0.0.1', serv_port), "sendto")
			data, host, port = serv.recvfrom
			assert_equal('bob', data, "read data match")
		ensure
			serv.close
		end
	end

end