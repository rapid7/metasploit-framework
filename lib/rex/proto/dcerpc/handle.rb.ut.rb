#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'rex/test'
require 'rex/exceptions'
require 'rex/proto/dcerpc/handle'

class Rex::Proto::DCERPC::Handle::UnitTest < Test::Unit::TestCase
	Klass = Rex::Proto::DCERPC::Handle

	def test_ncacn_np
		uuid = ['6bffd098-a112-3610-9833-46c3f87e345a', '1.0']
		protocol = 'ncacn_np'
		host  = '1.2.3.4'
		options = ['\wkssvc']
		i = Klass.new(uuid, protocol, host, options)
		assert(i, 'new')
		assert_equal('6bffd098-a112-3610-9833-46c3f87e345a:1.0@ncacn_np:1.2.3.4[\wkssvc]', i.to_s, 'as string')
		assert_equal(uuid, i.uuid, 'uuid')
		assert_equal(protocol, i.protocol, 'protocol')
		assert_equal(options, i.options, 'options')
	end
	
	def test_ncacn_ip_tcp
		uuid = ['6bffd098-a112-3610-9833-46c3f87e345a', '1.0']
		protocol = 'ncacn_ip_tcp'
		host  = '1.2.3.4'
		options = [80]
		i = Klass.new(uuid, protocol, host, options)
		assert(i, 'new')
		assert_equal('6bffd098-a112-3610-9833-46c3f87e345a:1.0@ncacn_ip_tcp:1.2.3.4[80]', i.to_s, 'as string')
		assert_equal(uuid, i.uuid, 'uuid')
		assert_equal(protocol, i.protocol, 'protocol')
		assert_equal(options, i.options, 'options')
	end
	
	def test_ncacn_ip_udp
		uuid = ['6bffd098-a112-3610-9833-46c3f87e345a', '1.0']
		protocol = 'ncacn_ip_udp'
		host  = '1.2.3.4'
		options = [80]
		i = Klass.new(uuid, protocol, host, options)
		assert(i, 'new')
		assert_equal('6bffd098-a112-3610-9833-46c3f87e345a:1.0@ncacn_ip_udp:1.2.3.4[80]', i.to_s, 'as string')
		assert_equal(uuid, i.uuid, 'uuid')
		assert_equal(protocol, i.protocol, 'protocol')
		assert_equal(options, i.options, 'options')
	end
	
	def test_ncacn_http
		uuid = ['6bffd098-a112-3610-9833-46c3f87e345a', '1.0']
		protocol = 'ncacn_http'
		host  = '1.2.3.4'
		options = [80]
		i = Klass.new(uuid, protocol, host, options)
		assert(i, 'new')
		assert_equal(i.to_s, '6bffd098-a112-3610-9833-46c3f87e345a:1.0@ncacn_http:1.2.3.4[80]', 'as string')
		assert_equal(uuid, i.uuid, 'uuid')
		assert_equal(protocol, i.protocol, 'protocol')
		assert_equal(options, i.options, 'options')
	end
	
	def test_invalid
		assert_raise(Rex::ArgumentError, 'invalid uuid') { Klass.new(['a', '1.0'], 'ncacn_ip_tcp', '1.2.3.4', [80]) }
		assert_raise(Rex::ArgumentError, 'invalid uuid version') { Klass.new(['6bffnd098-a112-3610-9833-46c3f87e345a', 'b'], 'ncacn_ip_tcp', '1.2.3.4', [80]) }
		assert_raise(Rex::ArgumentError, 'invalid proto') { Klass.new(['6bffnd098-a112-3610-9833-46c3f87e345a', '1.0'], 'ncacn_ip_bmc', '1.2.3.4', [80]) }
		assert_raise(Rex::ArgumentError, 'invalid empty uuid') { Klass.new([nil, '1.0'], 'ncacn_ip_tcp', '1.2.3.4', [80]) }
	end

	def test_parser
		handle = '6bffd098-a112-3610-9833-46c3f87e345a:1.0@ncacn_ip_tcp:10.4.10.10[80]'
		i = Klass.parse( handle )
		assert(i)
		assert_equal(['6bffd098-a112-3610-9833-46c3f87e345a', '1.0'], i.uuid, 'uuid')
		assert_equal('ncacn_ip_tcp', i.protocol, 'protocol')
		assert_equal('10.4.10.10', i.address, 'address')
		assert_equal(['80'], i.options, 'options')
	end

	def test_parser_invalid
		handle = '6bffd098-a112-3610-9833-46c3f87e345a:1.0@ncacn_ip_tcp:10.4.10.10[80'
		assert_raise(Rex::ArgumentError, 'invalid handle (parser)') { Klass.parse(handle) }
	end
end