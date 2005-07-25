#!/usr/bin/ruby

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
				req = Rex::Proto::Http::Request::Get.new('/')
				res = c.send_request(req)
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
			p   = Proc.new { |cli, req|
				resp = Rex::Proto::Http::Response::OK.new

				resp.body = "Chickens everywhere"
			
				cli.send_response(resp)
			}

			s.add_resource('/foo', 'Proc' => p)

			1.upto(10) { 
				req = Rex::Proto::Http::Request::Get.new('/foo')
				res = c.send_request(req)
				assert_not_nil(res)
				assert_equal(200, res.code)
				assert_equal("Chickens everywhere", res.body)
			}

			s.remove_resource('/foo')

			#
			# This stuff crashes ruby, possibly because, specifically sending the
			# request to the removed resource.  Seems like it causes it to
			# reference something that's been marked for GC
			#
			#req = Rex::Proto::Http::Request::Get.new('/foo')
			#res = c.send_request(req)
			#assert_not_nil(res)
			#assert_equal(404, res.code)
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
