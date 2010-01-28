#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'rex/test'
require 'rex/proto/drda/utils'
require 'rex/socket'

class Rex::Proto::DRDA::Utils::UnitTest < Test::Unit::TestCase

	Klass = Rex::Proto::DRDA

	def test_socket_connectivity
		assert_nothing_raised do
			socket = Rex::Socket.create_tcp(
				'PeerHost' => $_REX_TEST_DRDA_HOST.to_s, # PeerHost can be nil!
				'PeerPort' => 50000
			)
			assert_kind_of Socket, socket
			assert !socket.closed?
			socket.close
			assert socket.closed?
		end
	end

	def test_client_probe_create
		probe_pkt = Klass::Utils.client_probe
		assert_equal 54, probe_pkt.size
	end

	def test_client_probe
		probe_pkt = Klass::Utils.client_probe('toolsdb')
		begin
			Timeout.timeout($_REX_TEST_TIMEOUT) do
				socket = Rex::Socket.create_tcp(
					'PeerHost' => $_REX_TEST_DRDA_HOST.to_s, 
					'PeerPort' => 50000
				)
				sent = socket.put probe_pkt
				assert_equal 76, sent
				probe_reply = socket.get_once
				assert_operator probe_reply.size, :>=, 10
				parsed_reply = Klass::SERVER_PACKET.new.read probe_reply
				assert_kind_of Array, parsed_reply
				assert_equal parsed_reply[0].codepoint, Klass::Constants::EXCSATRD
				socket.close
			end
		rescue Timeout::Error
			flunk("Timed out")
		end
	end

	# Client auth requires a successful probe. This is a complete authentication
	# sequence, culminating in info[:db_login_sucess] returning either true or
	# false.
	def test_client_auth
		probe_pkt = Klass::Utils.client_probe('toolsdb')
		auth_pkt = Klass::Utils.client_auth(:dbname => 'toolsdb',
			:dbuser => $_REX_TEST_DRDA_USER.to_s,
			:dbpass => $_REX_TEST_DRDA_PASS.to_s
		)
		begin
			Timeout.timeout($_REX_TEST_TIMEOUT) do
				socket = Rex::Socket.create_tcp(
					'PeerHost' => $_REX_TEST_DRDA_HOST.to_s, 
					'PeerPort' => 50000
				)
				sent = socket.put probe_pkt
				probe_reply = socket.get_once
				sent = socket.put auth_pkt
				assert_equal(75, sent)
				auth_reply = socket.get_once
				parsed_auth_reply = Klass::SERVER_PACKET.new.read auth_reply
				info = Klass::Utils.server_packet_info(parsed_auth_reply)
				assert info[:db_login_success]
				socket.close
			end
		rescue Timeout::Error
			flunk("Timed out")
		end
	end

end

