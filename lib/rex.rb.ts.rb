#!/usr/bin/ruby -I..

require 'test/unit'
require 'rex'

require 'rex/exceptions.rb.ut'
require 'rex/transformer.rb.ut'
require 'rex/text.rb.ut'
require 'rex/evasion.rb.ut'
require 'rex/file.rb.ut'

require 'rex/arch/x86'

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
require 'rex/socket/switch_board.rb.ut'
require 'rex/socket/subnet_walker.rb.ut'

require 'rex/parser/arguments.rb.ut'

require 'rex/ui/text/color.rb.ut'
require 'rex/ui/text/table.rb.ut'

require 'rex/exploitation/egghunter.rb.ut'
require 'rex/exploitation/seh.rb.ut'

class Rex::TestSuite
	def self.suite
		suite = Test::Unit::TestSuite.new("Rex")

		# General
		suite << Rex::Exceptions::UnitTest.suite
		suite << Rex::Transformer::UnitTest.suite
		suite << Rex::Text::UnitTest.suite
		suite << Rex::Evasion::UnitTest.suite
		suite << Rex::File::UnitTest.suite

		# Arch
		suite << Rex::Arch::X86::UnitTest.suite

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
		suite << Rex::Socket::SslTcp::UnitTest.suite
		suite << Rex::Socket::TcpServer::UnitTest.suite
		suite << Rex::Socket::Udp::UnitTest.suite
		suite << Rex::Socket::Comm::Local::UnitTest.suite
		suite << Rex::Socket::SwitchBoard::UnitTest.suite
		suite << Rex::Socket::SubnetWalker::UnitTest.suite

		# Parsers
		suite << Rex::Parser::Arguments::UnitTest.suite

		# Ui
		suite << Rex::Ui::Color::Table::UnitTest.suite
		suite << Rex::Ui::Text::Table::UnitTest.suite

		# Exploitation
		suite << Rex::Exploitation::Egghunter::UnitTest.suite
		suite << Rex::Exploitation::Seh::UnitTest.suite

		return suite;
	end
end
