#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/proto/http'

class Rex::Proto::Http::Server::UnitTest < Test::Unit::TestCase

	ListenPort = 8090
	ListenHost = '127.0.0.1'

	SrvKlass = Rex::Proto::Http::Server
	CliKlass = Rex::Proto::Http::Client

	def test_server
		begin
			s   = start_srv
			c   = CliKlass.new(ListenHost, ListenPort)

			1.upto(10) { 
				req = c.request_raw('uri' => '/')
				res = c.send_recv(req)
				assert_not_nil(res)
				assert_equal(404, res.code)
			}
		ensure
			stop_srv
		end
	end

	def test_resource
		begin
			s   = start_srv
			c   = CliKlass.new(ListenHost, ListenPort)

			s.add_resource('/foo', 
				'Proc' => Proc.new { |cli, req|
					resp = Rex::Proto::Http::Response::OK.new

					resp.body = "Chickens everywhere"
				
					cli.send_response(resp)
				})

			1.upto(10) { 
				req = c.request_raw('uri' => '/foo')
				res = c.send_recv(req)
				assert_not_nil(res)
				assert_equal(200, res.code)
				assert_equal("Chickens everywhere", res.body)
			}

			s.remove_resource('/foo')

			req = c.request_raw('uri' => '/foo')
			res = c.send_recv(req)
			assert_not_nil(res)
			assert_equal(404, res.code)
		ensure
			stop_srv
		end
	end

protected

	def start_srv
		self.srv = SrvKlass.new(ListenPort, ListenHost)
		self.srv.start
		self.srv
	end

	def stop_srv
		self.srv.stop if (self.srv)
	end

attr_accessor :srv

end