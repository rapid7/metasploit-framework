#!/usr/bin/env ruby
require "test/unit"
require File.dirname(__FILE__) + "/../lib/robots"

module FakeHttp
  def content_type
    "text/plain"
  end
  
  def status
    ["200", "OK"]
  end
end

class TestRobots < Test::Unit::TestCase
  def setup
    def Robots.get_robots_txt(uri, user_agent)
      fixture_file = File.dirname(__FILE__) + "/fixtures/" + uri.host.split(".")[-2] + ".txt"
      File.open(fixture_file).extend(FakeHttp)
    end
    
    @robots = Robots.new "Ruby-Robot.txt Parser Test Script"
  end
  
  def test_allowed_if_no_robots
    def Robots.get_robots_txt(uri, user_agent)
      return nil
    end
    
    assert_allowed("somesite", "/")
  end
  
  def test_disallow_nothing
    assert_allowed("emptyish", "/")
    assert_allowed("emptyish", "/foo")
  end
  
  def test_reddit
    assert_allowed("reddit", "/")
  end
  
  def test_other
    assert_allowed("yelp", "/foo")
    assert_disallowed("yelp", "/mail?foo=bar")
  end
  
  def test_site_with_disallowed
    assert_allowed("google", "/")
  end
  
  def test_other_values
    sitemap = {"Sitemap" => ["http://www.eventbrite.com/sitemap_index.xml", "http://www.eventbrite.com/sitemap_index.xml"]}
    assert_other_equals("eventbrite", sitemap)
  end
  
  def assert_other_equals(name, value)
    assert_equal(value, @robots.other_values(uri_for_name(name, "/")))
  end
  
  def assert_allowed(name, path)
    assert_allowed_equals(name, path, true)
  end
  
  def assert_disallowed(name, path)
    assert_allowed_equals(name, path, false)
  end
  
  def assert_allowed_equals(name, path, value)
    assert_equal(value, @robots.allowed?(uri_for_name(name, path)), @robots.inspect)
  end
  
  def uri_for_name(name, path)
    uri = name.nil? ? nil : "http://www.#{name}.com#{path}"
  end
    
end