require 'rubygems'
require 'bundler/setup'

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift(File.dirname(__FILE__))

require "minitest/autorun"
require 'test/unit'
require 'pcaprub'


if RUBY_VERSION >= "1.9.2"
  require 'coveralls'
  Coveralls.wear!
end

