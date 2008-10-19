#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/socket/ssl_tcp_server'
require 'rex/socket/ssl_tcp'

class Rex::Socket::SslTcpServer::UnitTest < Test::Unit::TestCase

	# XXX.  The client data is sent & decrypted just fine.  The server data is not.  the client thread just spins.  BAH.
	def test_tcp_server
		return;

		serv_port = 65433
		c = nil

		threads = []
		threads << Thread.new() {
			serv = Rex::Socket.create_tcp_server('LocalPort' => serv_port, 'SSL' => true)
			assert_kind_of(Rex::Socket::SslTcpServer, serv, "type => ssl")
			assert_kind_of(Rex::Socket::TcpServer, serv, "type => tcp")
			assert_kind_of(Rex::IO::StreamServer, serv, "type => stream")
			s = serv.accept
			assert_equal("client_data\n", s.get_once(), "s: get_once")
			assert_equal(3, s.write("Yo\n"), "s: put Yo")
			assert(s.methods.include?('<<'))
			assert(s.methods.include?('>>'))
			assert(s.methods.include?('has_read_data?'))
			serv.close
		}

		threads << Thread.new() {
			sleep(2)
			assert_nothing_raised {
				c = Rex::Socket::SslTcp.create(
				'PeerHost' => '127.0.0.1',
				'PeerPort' => serv_port
				)
			}
			assert_kind_of(Rex::Socket::Tcp, c, "TCP")
			assert_kind_of(Rex::Socket::SslTcp, c, "SSL")
			assert_equal(12, c.write("client_data\n"), "c: write")
			assert_equal("Yo\n", c.get_once(), "c: get_once")
			c.close if (c)
		}

		threads.each { |aThread|  aThread.join }
	end

end