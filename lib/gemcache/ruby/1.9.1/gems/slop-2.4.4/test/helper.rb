unless Object.const_defined? 'Slop'
  $:.unshift File.expand_path('../../lib', __FILE__)
  require 'slop'
end

require 'minitest/autorun'
require 'stringio'

class TestCase < MiniTest::Unit::TestCase
  def self.test(name, &block)
    define_method("test_#{name.gsub(/\W/, '_')}", &block) if block
  end
end