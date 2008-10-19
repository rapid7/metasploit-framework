#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'msf/core'

module Msf

class Module::Reference::UnitTest < Test::Unit::TestCase
	def test_ref
		assert_equal('some cool book', Reference.from_s('some cool book').to_s)
	end

	def test_site_ref
		assert_equal('ftp://www.google.com', SiteReference.from_s('ftp://www.google.com').to_s)
		assert_equal('http://www.google.com', SiteReference.from_s('http://www.google.com').to_s)
		assert_equal('https://www.google.com', SiteReference.from_s('https://www.google.com').to_s)
		assert_equal('http://www.osvdb.org/1', SiteReference.from_a([ 'OSVDB', 1 ]).to_s)
		assert_equal('http://www.osvdb.org/1', SiteReference.from_a([ 'OSVDB', 1 ]).to_s)
		assert_equal('jones (a)', SiteReference.from_a([ 'jones', 'a' ]).to_s)
		assert_nil(SiteReference.from_s('whatever invalid shizzy'))
	end
end

end