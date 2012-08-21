#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'test/unit'
require 'net/ssh'

$_SSH_TEST_SERVERNAME = 'dbsrv'     # Name or IP, default: dbsrv
$_SSH_TEST_SERVERPORT =  22         # Default: 22
$_SSH_TEST_USERNAME   = 'user'      # Default: scott
$_SSH_TEST_PASSWORD   = 'useruser'  # Default: tiger
$_SSH_TEST_OS         = 'Linux'     # Default: Linux

class Net::SSH::UnitTest < ::Test::Unit::TestCase

	# Need to do this or else we're talking about
	# some other Net::SSH.
	def test_local_version
		if Net::SSH::Version::CURRENT.respond_to? :msf3
			assert Net::SSH::Version::CURRENT.msf3
		else
			flunk "Not testing the MSF3 bundled version of SSH" 
		end
	end

	# Tests that a connection happens, that failed logins
	# are recorded, and that we're using Rex sockets instead
	# of standard sockets.
	def test_connection

		assert_nothing_raised do
			conn = Net::SSH.start(
				$_SSH_TEST_SERVERNAME,
				$_SSH_TEST_USERNAME,
				:password => $_SSH_TEST_PASSWORD,
				:auth_methods => ['password'],
				:port => $_SSH_TEST_SERVERPORT
			)
			conn.close
		end

		assert_raise Net::SSH::AuthenticationFailed do
			conn = Net::SSH.start(
				$_SSH_TEST_SERVERNAME,
				$_SSH_TEST_USERNAME,
				:password => $_SSH_TEST_PASSWORD+"bad",
				:auth_methods => ['password'],
				:port => $_SSH_TEST_SERVERPORT
			)
			conn.close
		end
	end

	def test_rex_sockets
			conn = Net::SSH.start(
				$_SSH_TEST_SERVERNAME,
				$_SSH_TEST_USERNAME,
				:password => $_SSH_TEST_PASSWORD,
				:auth_methods => ['password'],
				:port => $_SSH_TEST_SERVERPORT
			)
		assert_kind_of Rex::Socket::Tcp, conn.transport.socket
		conn.close
	end

	def _do_uname(host,user,pass)
		ret = nil
		conn = Net::SSH.start(
			host,
			user,
			:password => pass,
			:auth_methods => ['password'],
			:port => 22
		) do |ssh|
			ret = ssh.exec!('/bin/uname -a')
			ssh.loop
		end
		return ret
	end

	def test_simple_exec
		uname_ret = nil
		assert_nothing_raised do
		uname_ret = _do_uname(
				$_SSH_TEST_SERVERNAME,
				$_SSH_TEST_USERNAME,
				$_SSH_TEST_PASSWORD
			)
		end

		assert_match(/^#{$_SSH_TEST_OS}/, uname_ret)
	end
end
