#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/socket/parameters'

class Rex::Socket::Parameters::UnitTest < Test::Unit::TestCase

	def test_parameters
		h = { 
				'PeerHost'  => 'phost',
				'PeerPort'  => 12,
				'LocalHost' => 'lhost',
				'LocalPort' => 47,
				'Bare'      => true,
				'Server'    => true,
				'Comm'      => 'nothing',
				'Proto'     => 'tcp',
				'SSL'       => true
		    }

		p = Rex::Socket::Parameters.from_hash(h)

		assert_equal('phost', p.peerhost, "peerhost")
		assert_equal('phost', p.peeraddr, "peeraddr")
		assert_equal(12, p.peerport, "peerport")
		assert_equal('lhost', p.localhost, "localhost")
		assert_equal('lhost', p.localaddr, "localaddr")
		assert_equal(47, p.localport, "localport")
		assert_equal(true, p.bare?, "bare")
		assert_equal(true, p.server?, "server")
		assert_equal(false, p.client?, "client")
		assert_equal('nothing', p.comm, "comm")
		assert_equal(true, p.tcp?, "proto tcp")
		assert_equal(false, p.udp?, "proto udp")
		assert_equal(true, p.ssl, "ssl")

		p = Rex::Socket::Parameters.from_hash({})

		assert_equal(nil, p.peerhost, "null peerhost")
		assert_equal('0.0.0.0', p.localhost, "default localhost")
		assert_equal(0, p.peerport, "0 peerport")
		assert_equal(0, p.localport, "0 localport")
		assert_equal(false, p.bare, "default false bare")
		assert_equal('tcp', p.proto, "default tcp proto")
		assert_equal(false, p.server, "default false server")
		assert_equal(false, p.ssl, "default false ssl")
	end

end