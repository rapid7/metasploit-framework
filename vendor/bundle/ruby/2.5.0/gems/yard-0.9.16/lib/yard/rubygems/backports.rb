# frozen_string_literal: true
begin
  require 'rubygems'
  if defined?(Gem::VERSION) && Gem::VERSION >= '1.8.0'
    require File.dirname(__FILE__) + '/backports/gem'
    require File.dirname(__FILE__) + '/backports/source_index'
  end
rescue LoadError
  nil # noop
end
