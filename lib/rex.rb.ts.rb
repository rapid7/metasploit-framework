#!/usr/bin/ruby

require 'test/unit'
require 'rex'

require 'rex/exceptions.rb.ut'
require 'rex/transformer.rb.ut'

require 'rex/encoding/xor/generic.rb.ut'
require 'rex/encoding/xor/byte.rb.ut'
require 'rex/encoding/xor/word.rb.ut'
require 'rex/encoding/xor/dword.rb.ut'
require 'rex/encoding/xor/dword_additive.rb.ut'

require 'rex/socket.rb.ut'
require 'rex/socket/tcp.rb.ut'
require 'rex/socket/ssl_tcp.rb.ut'
require 'rex/socket/tcp_server.rb.ut'
require 'rex/socket/udp.rb.ut'
require 'rex/socket/parameters.rb.ut'
require 'rex/socket/comm/local.rb.ut'

require 'rex/ui/text/table.rb.ut'

class Rex::TestSuite
	def self.suite
		suite = Test::Unit::TestSuite.new("Rex")

		# General
		suite << Rex::Exceptions::UnitTest.suite
		suite << Rex::Transformer::UnitTest.suite

		# Encoding
		suite << Rex::Encoding::Xor::Generic::UnitTest.suite
		suite << Rex::Encoding::Xor::Byte::UnitTest.suite
		suite << Rex::Encoding::Xor::Word::UnitTest.suite
		suite << Rex::Encoding::Xor::Dword::UnitTest.suite
		suite << Rex::Encoding::Xor::DwordAdditive::UnitTest.suite

		# Sockets
		suite << Rex::Socket::UnitTest.suite
		suite << Rex::Socket::Parameters::UnitTest.suite
		suite << Rex::Socket::Tcp::UnitTest.suite
#		suite << Rex::Socket::SslTcp::UnitTest.suite
		suite << Rex::Socket::TcpServer::UnitTest.suite
		suite << Rex::Socket::Udp::UnitTest.suite
		suite << Rex::Socket::Comm::Local::UnitTest.suite

		# Ui
		suite << Rex::Ui::Text::Table::UnitTest.suite

		return suite;
	end
end
