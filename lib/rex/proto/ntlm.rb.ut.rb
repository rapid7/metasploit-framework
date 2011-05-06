#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/proto/ntlm'
require 'rex/socket'

class ConnectionTest < Test::Unit::TestCase
	def setup
		@user = "admin"
		@pass = "1234"
		@domain = ""
		@host = "192.168.145.161"
	end

	def test_socket_connectivity
		assert_nothing_raised do
			socket = Rex::Socket.create_tcp(
				'PeerHost' => @host,
				'PeerPort' => 80
			)
			assert_kind_of Socket, socket
			assert !socket.closed?
			socket.close
			assert socket.closed?
		end
	end

	def http_message(msg)
		get_req = "GET / HTTP/1.1\r\n"
		get_req += "Host: #{@host}\r\n"
		get_req += "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
		get_req += "Authorization: NTLM #{msg.encode64}\r\n"
		get_req += "Content-type: application/x-www-form-urlencoded\r\n"
		get_req += "Content-Length: 0\r\n"
		get_req += "\r\n"
	end

	def client_auth(pw)
		msg_1 = Rex::Proto::NTLM::Message::Type1.new
		get_req = http_message(msg_1)
		socket = Rex::Socket.create_tcp(
			'PeerHost' => @host,
			'PeerPort' => 80
		)
		socket.put get_req
		res = socket.get(3)
		assert res =~ /WWW-Authenticate: NTLM TlRM/
			res_ntlm = res.match(/WWW-Authenticate: NTLM ([A-Z0-9\x2b\x2f=]+)/i)[1]
		assert_operator res_ntlm.size, :>=, 24
		msg_2 = Rex::Proto::NTLM::Message.decode64(res_ntlm)
		assert msg_2
		msg_3 = msg_2.response({:user => @user, :password => pw}, {:ntlmv2 => true})
		assert msg_3
		auth_req = http_message(msg_3)
		socket.put auth_req
		auth_res = socket.get(3)
		socket.close
		return auth_res
	end

	def test_client_auth_success
		assert_equal client_auth(@pass)[0,12], "HTTP/1.1 200"
	end

	def test_client_auth_fail
		assert_not_equal client_auth("badpass")[0,12], "HTTP/1.1 200"
		assert_equal client_auth("badpass")[0,12], "HTTP/1.1 401"
	end
end

# FunctionTest by Minero Aoki

class FunctionTest < Test::Unit::TestCase #:nodoc:
	def setup
		@passwd = "SecREt01"
		@user   = "user"
		@domain = "domain"
		@challenge = ["0123456789abcdef"].pack("H*")
		@client_ch = ["ffffff0011223344"].pack("H*")
		@timestamp = 1055844000
		@trgt_info = [
			"02000c0044004f004d00410049004e00" +
			"01000c00530045005200560045005200" +
			"0400140064006f006d00610069006e00" +
			"2e0063006f006d000300220073006500" +
			"72007600650072002e0064006f006d00" +
			"610069006e002e0063006f006d000000" +
			"0000"
		].pack("H*")
	end

	def test_lm_hash
		ahash = ["ff3750bcc2b22412c2265b23734e0dac"].pack("H*")
		assert_equal ahash, Rex::Proto::NTLM::Crypt::lm_hash(@passwd)
	end

	def test_ntlm_hash
		ahash = ["cd06ca7c7e10c99b1d33b7485a2ed808"].pack("H*")
		assert_equal ahash, Rex::Proto::NTLM::Crypt::ntlm_hash(@passwd)
	end

	def test_ntlmv2_hash
		ahash = ["04b8e0ba74289cc540826bab1dee63ae"].pack("H*")
		assert_equal ahash, Rex::Proto::NTLM::Crypt::ntlmv2_hash(@user, @passwd, @domain)
	end

	def test_lm_response
		ares = ["c337cd5cbd44fc9782a667af6d427c6de67c20c2d3e77c56"].pack("H*")
		assert_equal ares, Rex::Proto::NTLM::Crypt::lm_response(
			{
			:lm_hash => Rex::Proto::NTLM::Crypt::lm_hash(@passwd),
			:challenge => @challenge
		}
		)
	end

	def test_ntlm_response
		ares = ["25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6"].pack("H*")
		ntlm_hash = Rex::Proto::NTLM::Crypt::ntlm_hash(@passwd)
		assert_equal ares, Rex::Proto::NTLM::Crypt::ntlm_response(
			{
			:ntlm_hash => ntlm_hash,
			:challenge => @challenge
		}
		)
	end

	def test_lmv2_response
		ares = ["d6e6152ea25d03b7c6ba6629c2d6aaf0ffffff0011223344"].pack("H*")
		assert_equal ares, Rex::Proto::NTLM::Crypt::lmv2_response(
			{
			:ntlmv2_hash => Rex::Proto::NTLM::Crypt::ntlmv2_hash(@user, @passwd, @domain),
			:challenge => @challenge
		},
			{ :client_challenge => @client_ch }
		)
	end

	def test_ntlmv2_response
		ares = [
			"cbabbca713eb795d04c97abc01ee4983" +
			"01010000000000000090d336b734c301" +
			"ffffff00112233440000000002000c00" +
			"44004f004d00410049004e0001000c00" +
			"53004500520056004500520004001400" +
			"64006f006d00610069006e002e006300" +
			"6f006d00030022007300650072007600" +
			"650072002e0064006f006d0061006900" +
			"6e002e0063006f006d00000000000000" +
			"0000"
		].pack("H*")
		assert_equal ares, Rex::Proto::NTLM::Crypt::ntlmv2_response(
			{
			:ntlmv2_hash => Rex::Proto::NTLM::Crypt::ntlmv2_hash(@user, @passwd, @domain),
			:challenge => @challenge,
			:target_info => @trgt_info
		},
			{
			:timestamp => @timestamp,
			:client_challenge => @client_ch
		}
		)
	end

	def test_ntlm2_session
		acha = ["ffffff001122334400000000000000000000000000000000"].pack("H*")
		ares = ["10d550832d12b2ccb79d5ad1f4eed3df82aca4c3681dd455"].pack("H*")
		session = Rex::Proto::NTLM::Crypt::ntlm2_session(
			{
			:ntlm_hash => Rex::Proto::NTLM::Crypt::ntlm_hash(@passwd),
			:challenge => @challenge
		},
			{ :client_challenge => @client_ch }
		)
		assert_equal acha, session[0]
		assert_equal ares, session[1]
	end
end
