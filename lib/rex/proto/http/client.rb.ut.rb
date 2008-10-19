#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/proto/http'

class Rex::Proto::Http::Client::UnitTest < Test::Unit::TestCase

	Klass = Rex::Proto::Http::Client

	def test_parse
		c = Klass.new('www.google.com')

		# Set request factory parameters
		c.set_config(
			'vhost'      => 'www.google.com',
			'agent'      => 'Metasploit Framework/3.0',
			'version'    => '1.1',
			'cookie'     => 'NoCookie=NotACookie'
		)

		# Set client parameters
		c.set_config(
			'read_max_data' => 1024 * 1024
		)

		#
		# Request the main web pagfe
		#
		r = c.request_raw(
			'method' => 'GET',
			'uri'    => '/'
		)

		resp = c.send_recv(r)

		assert_equal(200, resp.code)
		assert_equal('OK', resp.message)
		assert_equal('1.1', resp.proto)

		#
		# Request a file that does not exist
		#
		r = c.request_raw(
			'method' => 'GET',
			'uri'    => '/NoFileHere.404'
		)

		resp = c.send_recv(r)
		
		assert_equal(404, resp.code)
		assert_equal('Not Found', resp.message)
		assert_equal('1.1', resp.proto)
		
		
		#
		# Send a POST request that results in a 302
		#
		c = Klass.new('beta.microsoft.com')
		c.set_config('vhost' => 'beta.microsoft.com')

		r = c.request_cgi(
			'method' => 'POST',
			'uri'    => '/',
			'vars_post'  => { 'var' => 'val' },
			'ctype' => 'application/x-www-form-urlencoded'
		)

		resp = c.send_recv(r)

		assert_equal(200, resp.code)
		assert_equal('OK', resp.message)
		assert_equal('1.1', resp.proto)
	end

	def test_ssl
		c = Klass.new('www.geotrust.com', 443, {}, true)
		c.set_config('vhost' => 'www.geotrust.com')
		r = c.request_raw(
			'method' => 'GET',
			'uri'    => '/'
		)
		resp = c.send_recv(r)
		assert_equal(200, resp.code)
		assert_equal('OK', resp.message)
		assert_equal('1.1', resp.proto)
		c.close
	end

end