#!/usr/bin/env ruby

require 'test/unit'
require 'test/unit/assertions'
begin
  require 'ruby-debug'
rescue LoadError
  puts "Couldn't load ruby-debug. gem install ruby-debug if you need it."
end
require File.join(File.dirname(__FILE__), '..', 'lib', 'liquid')


module Test
  module Unit
    module Assertions
      include Liquid

      def assert_template_result(expected, template, assigns = {}, message = nil)
        assert_equal expected, Template.parse(template).render(assigns)
      end

      def assert_template_result_matches(expected, template, assigns = {}, message = nil)
        return assert_template_result(expected, template, assigns, message) unless expected.is_a? Regexp

        assert_match expected, Template.parse(template).render(assigns)
      end
    end # Assertions
  end # Unit
end # Test
