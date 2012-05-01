#!/usr/bin/env ruby
here = File.dirname(__FILE__)
require "#{here}/test_helper"

begin
require 'json'
rescue LoadError
require 'rubygems'
require 'json'
end

CASES_PATH         = "#{here}/cases.mpac"
CASES_COMPACT_PATH = "#{here}/cases_compact.mpac"
CASES_JSON_PATH    = "#{here}/cases.json"

class MessagePackTestCases < Test::Unit::TestCase
	def feed_file(path)
		pac = MessagePack::Unpacker.new
		pac.feed File.read(path)
		pac
	end

	def test_compare_compact
		pac  = feed_file(CASES_PATH)
		cpac = feed_file(CASES_COMPACT_PATH)

		 objs = [];  pac.each {| obj|  objs <<  obj }
		cobjs = []; cpac.each {|cobj| cobjs << cobj }

		objs.zip(cobjs).each {|obj, cobj|
			assert_equal(obj, cobj)
		}
	end

	def test_compare_json
		pac  = feed_file(CASES_PATH)

		objs = []; pac.each {|obj| objs <<  obj }
		jobjs = JSON.load File.read(CASES_JSON_PATH)

		objs.zip(jobjs) {|obj, jobj|
			assert_equal(obj, jobj)
		}
	end
end

