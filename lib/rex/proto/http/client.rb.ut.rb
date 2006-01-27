#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/proto/http'

class Rex::Proto::Http::Client::UnitTest < Test::Unit::TestCase

	Klass = Rex::Proto::Http::Client

	def test_parse
		c = Klass.new('www.google.com')

		# Set request factory parameters
		c.config(
			'vhost'      => 'www.google.com',
			'user-agent' => 'Metasploit Framework/3.0',
			'proto'      => '1.1',
			'cookie'     => 'NoCookie=NotACookie'
		)

		# Set client parameters
		c.config(
			'max-data' => 1024 * 1024
		)

		#
		# Request the main web pagfe
		#
		r = c.request(
			'method' => 'GET',
			'uri'    => '/'
		)

		resp = c.send_request(r)

		assert_equal(200, resp.code)
		assert_equal('OK', resp.message)
		assert_equal('1.1', resp.proto)

		#
		# Request a file that does not exist
		#
		r = c.request(
			'method' => 'GET',
			'uri'    => '/NoFileHere.404'
		)

		resp = c.send_request(r)
		
		assert_equal(404, resp.code)
		assert_equal('Not Found', resp.message)
		assert_equal('1.1', resp.proto)
		
		
		#
		# Send a POST request that results in a 302
		#
		c = Klass.new('beta.microsoft.com')
		c.request_option('vhost', 'beta.microsoft.com')

		r = c.request(
			'method' => 'POST',
			'uri'    => '/',
			'data'   => 'var=val',
			'content-type' => 'application/x-www-form-urlencoded'
		)

		resp = c.send_request(r)

		assert_equal(302, resp.code)
		assert_equal('Object moved', resp.message)
		assert_equal('1.1', resp.proto)
	end

	def test_ssl
		c = Klass.new('www.geotrust.com', '443', {}, 'true')
		c.request_option('vhost', 'www.geotrust.com')
		r = c.request(
			'method' => 'GET',
			'uri'    => '/'
		)
		resp = c.send_request(r)
		assert_equal(200, resp.code)
		assert_equal('OK', resp.message)
		assert_equal('1.1', resp.proto)
		c.close
	end

	def test_junk_pipeline
		host = 'www.apache.org'
		client = Klass.new(host)
		client.junk_pipeline = 5
		client.request_option('vhost', host)
		request = client.request('method' => 'GET', 'uri' => '/no-such-uri.html')
		response = client.send_request(request)
		assert_equal(404, response.code, 'pipeline response')
		client.close
	end

end
