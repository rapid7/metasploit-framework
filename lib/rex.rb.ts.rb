#!/usr/bin/ruby

require 'test/unit'
require 'Rex'

require 'Rex/Transformer.rb.ut'

require 'Rex/Encoding/Xor/Generic.rb.ut'
require 'Rex/Encoding/Xor/Byte.rb.ut'
require 'Rex/Encoding/Xor/Word.rb.ut'
require 'Rex/Encoding/Xor/DWord.rb.ut'
require 'Rex/Encoding/Xor/DWordAdditive.rb.ut'

require 'Rex/Socket.rb.ut'
require 'Rex/Socket/Tcp.rb.ut'
require 'Rex/Socket/SslTcp.rb.ut'
require 'Rex/Socket/TcpServer.rb.ut'
require 'Rex/Socket/Udp.rb.ut'
require 'Rex/Socket/Parameters.rb.ut'
require 'Rex/Socket/Comm/Local.rb.ut'

class Rex::TestSuite
	def self.suite
		suite = Test::Unit::TestSuite.new("Rex")

		# General
		suite << Rex::Transformer::UnitTest.suite

		# Encoding
		suite << Rex::Encoding::Xor::Generic::UnitTest.suite
		suite << Rex::Encoding::Xor::Byte::UnitTest.suite
		suite << Rex::Encoding::Xor::Word::UnitTest.suite
		suite << Rex::Encoding::Xor::DWord::UnitTest.suite
		suite << Rex::Encoding::Xor::DWordAdditive::UnitTest.suite

		# Sockets
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
