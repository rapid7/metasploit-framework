#!/usr/bin/ruby

require 'test/unit'
require 'Rex'
require 'Rex/Socket.rb.ut'
require 'Rex/Socket/Tcp.rb.ut'
require 'Rex/Socket/SslTcp.rb.ut'
require 'Rex/Socket/TcpServer.rb.ut'
require 'Rex/Socket/Udp.rb.ut'
require 'Rex/Socket/Parameters.rb.ut'
require 'Rex/Socket/Comm/Local.rb.ut'

class Rex::TestSuite
	def self.suite
		suite = Test::Unit::TestSuite.new

		suite << Rex::Socket::UnitTest.suite
		suite << Rex::Socket::Parameters::UnitTest.suite
		suite << Rex::Socket::Tcp::UnitTest.suite
		suite << Rex::Socket::SslTcp::UnitTest.suite
		suite << Rex::Socket::TcpServer::UnitTest.suite
		suite << Rex::Socket::Udp::UnitTest.suite
		suite << Rex::Socket::Comm::Local::UnitTest.suite

		return suite;
	end
end
