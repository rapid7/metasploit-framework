#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex'

class Rex::Socket::Tcp::UnitTest < Test::Unit::TestCase

	def test_tcp
		port = 65434
		listener = Rex::Socket.create_tcp_server( 'LocalPort' => port )
		client = nil

		begin
			# Connect to the temp server
			assert_nothing_raised {
				client = Rex::Socket.create_tcp(
					'PeerHost' => '127.0.0.1',
					'PeerPort' => port)
			}

			assert_kind_of(Rex::Socket::Tcp, client, 'kindof?')
			assert_equal('127.0.0.1', client.peerhost, 'peerhost')
			assert_equal(port, client.peerport, 'peerport')

			# Accept the client connection
			server = listener.accept
			assert_kind_of(Socket, server, "valid server socket connection")

			# do all of the tests, once for each side
			{ 'c/s' => [client, server], 's/c' => [server, client] }.each_pair { |mode, sockets|
				a = sockets[0]
				b = sockets[1]

				string = "test\n"
				assert_equal(false, a.has_read_data?(1), "#{mode} : has_read_data?, no data")
				assert_equal(string.length, b.write(string), "#{mode} : write")
				assert_equal(true, a.has_read_data?(1), "#{mode} : has_read_data?, with data")
				assert_equal(string, a.recv(string.length), "#{mode} : recv")

				string = "string\rtest\nwith\x00null"
				assert_equal(string.length, a << string, "#{mode} : append")
				tmp = ''; tmp = b.>>
				assert_equal(string, tmp, "#{mode} : append (reverse)")

				string = "\x00foobar\x00"
				assert_equal(string.length, a.send(string, 0), "#{mode} : send")
				assert_equal(string, b.get(), "#{mode} : get")
			}

			assert_equal(true, client.shutdown(::Socket::SHUT_RD), 'client: shutdown read handle')
			assert_equal(true, client.shutdown(::Socket::SHUT_WR), 'client: shutdown write handle')
			assert_nothing_raised {
				client.close
				client = nil
			}
		ensure
			client.close if (client)
			listener.close
		end
	end

end