module Backports
  TARGET_VERSION = caller.each{|c| break $1 if c =~ /set_version\/(\d\.\d\.\d)\.rb/}
end

unless Object.const_defined?(:Enumerator) || Backports::TARGET_VERSION < '1.9'
  require 'enumerator'
  # Needed for mspec:
  Enumerator = Enumerable::Enumerator
end

if RUBY_VERSION < Backports::TARGET_VERSION && Backports::TARGET_VERSION >= '1.9'
  require 'backports/1.9.2/float/infinity.rb' # Used in many specs...
  require 'backports/1.9.2/float/nan.rb' # Used in many specs...
end

def frozen_error_class
  begin
    [1].freeze.pop
  rescue Exception => e
    e.class
  end
end
