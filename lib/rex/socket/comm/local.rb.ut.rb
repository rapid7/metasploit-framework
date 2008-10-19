#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/exceptions'
require 'rex/socket/parameters'
require 'rex/socket/comm/local'

class Rex::Socket::Comm::Local::UnitTest < Test::Unit::TestCase

	def test_create_tcp
		test_port   = 64432
		test_server = TCPServer.new('127.0.0.1', test_port)

		# Create a stream connection to the stub listener
		stream = nil

		assert_nothing_raised {
			stream = Rex::Socket::Comm::Local.create(
				Rex::Socket::Parameters.from_hash(
					'PeerHost' => '127.0.0.1',
					'PeerPort' => test_port,
					'Proto'    => 'tcp'))
		}

		assert_kind_of(Rex::IO::Stream, stream, "valid Stream instance")
		assert_kind_of(Rex::Socket::Tcp, stream, "valid Tcp instance")
		stream.close

		# Now create a bare connection to the listener
		stream = nil

		assert_nothing_raised {
			stream = Rex::Socket::Comm::Local.create(
				Rex::Socket::Parameters.from_hash(
					'PeerHost' => '127.0.0.1',
					'PeerPort' => test_port,
					'Proto'    => 'tcp',
					'Bare'     => true))
		}

		assert_kind_of(Socket, stream, "valid Socket instance")

		assert_raise(Rex::ConnectionRefused, "connection refused failed") {
			Rex::Socket::Comm::Local.create(
				Rex::Socket::Parameters.from_hash(
					'PeerHost' => '127.0.0.1',
					'PeerPort' => 1,
					'Proto'    => 'tcp',
					'Bare'     => true))
		}

		stream.close

		test_server.close
	end

	def test_create_tcp_server
		# TODO
	end

	def test_create_udp
		# TODO
	end

	def test_create_invalid
		assert_raise(Rex::UnsupportedProtocol, "invalid protocol check failed") {
			Rex::Socket::Comm::Local.create(
				Rex::Socket::Parameters.from_hash(
					'Proto' => 'invalid'))
		}
	end

end