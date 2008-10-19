#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/socket/tcp_server'

class Rex::Socket::TcpServer::UnitTest < Test::Unit::TestCase

	def test_tcp_server
		serv_port = 65433
		serv = Rex::Socket.create_tcp_server(
			'LocalPort' => serv_port)
		ccli = nil

		begin
			assert_kind_of(Rex::Socket::TcpServer, serv, "valid TcpServer")
			assert_kind_of(Rex::IO::StreamServer, serv, "valid StreamServer")

			# Connect to the server
			assert_nothing_raised {
				ccli = Rex::Socket.create_tcp(
					'PeerHost' => '127.0.0.1',
					'PeerPort' => serv_port)
			}
			assert_kind_of(Rex::Socket::Tcp, ccli, "valid client client Tcp")

			# Accept the client connection
			scli = serv.accept
			assert_kind_of(Rex::Socket::Tcp, scli, "valid server client Tcp")

			assert_equal(2, scli.put("Yo"), "scli: put Yo")
			assert_equal("Yo", ccli.get(), "ccli: get Yo")
			assert(scli.methods.include?('<<'))
			assert(scli.methods.include?('>>'))
			assert(scli.methods.include?('has_read_data?'))
			
		ensure
			ccli.close if (ccli)
			serv.close
		end
	end

end