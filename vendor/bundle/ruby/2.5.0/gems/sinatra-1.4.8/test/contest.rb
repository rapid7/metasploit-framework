# Copyright (c) 2009 Damian Janowski and Michel Martens for Citrusbyte
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
require "rubygems"
require "minitest/autorun"

# Contest adds +teardown+, +test+ and +context+ as class methods, and the
# instance methods +setup+ and +teardown+ now iterate on the corresponding
# blocks. Note that all setup and teardown blocks must be defined with the
# block syntax. Adding setup or teardown instance methods defeats the purpose
# of this library.
class Minitest::Test
  def self.setup(&block)     setup_blocks    << block  end
  def self.teardown(&block)  teardown_blocks << block  end
  def self.setup_blocks()    @setup_blocks    ||= []   end
  def self.teardown_blocks() @teardown_blocks ||= []   end

  def setup_blocks(base = self.class)
    setup_blocks base.superclass if base.superclass.respond_to? :setup_blocks
    base.setup_blocks.each do |block|
      instance_eval(&block)
    end
  end

  def teardown_blocks(base = self.class)
    teardown_blocks base.superclass if base.superclass.respond_to? :teardown_blocks
    base.teardown_blocks.each do |block|
      instance_eval(&block)
    end
  end

  alias setup setup_blocks
  alias teardown teardown_blocks

  def self.context(*name, &block)
    subclass = Class.new(self)
    remove_tests(subclass)
    subclass.class_eval(&block) if block_given?
    const_set(context_name(name.join(" ")), subclass)
  end

  def self.test(name, &block)
    define_method(test_name(name), &block)
  end

  class << self
    alias_method :should, :test
    alias_method :describe, :context
  end

private

  def self.context_name(name)
    # "Test#{sanitize_name(name).gsub(/(^| )(\w)/) { $2.upcase }}".to_sym
    name = "Test#{sanitize_name(name).gsub(/(^| )(\w)/) { $2.upcase }}"
    name.tr(" ", "_").to_sym
  end

  def self.test_name(name)
    name = "test_#{sanitize_name(name).gsub(/\s+/,'_')}_0"
    name = name.succ while method_defined? name
    name.to_sym
  end

  def self.sanitize_name(name)
    # name.gsub(/\W+/, ' ').strip
    name.gsub(/\W+/, ' ')
  end

  def self.remove_tests(subclass)
    subclass.public_instance_methods.grep(/^test_/).each do |meth|
      subclass.send(:undef_method, meth.to_sym)
    end
  end
end
