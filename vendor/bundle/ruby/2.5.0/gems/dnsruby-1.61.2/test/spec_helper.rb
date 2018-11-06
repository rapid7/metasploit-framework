if ENV['RUN_EXTRA_TASK'] == 'TRUE'
  require 'coveralls'
  Coveralls.wear!

  require 'simplecov'

  # SimpleCov.formatter = SimpleCov::Formatter::MultiFormatter.new(
      # [SimpleCov::Formatter::HTMLFormatter, Coveralls::SimpleCov::Formatter])
  SimpleCov.formatter = Coveralls::SimpleCov::Formatter
  SimpleCov.start do
    add_filter 'test/'
  end
end

require 'minitest'
require 'minitest/autorun'
require 'minitest/display'

MiniTest::Display.options = {
  suite_names: true,
  color: true,
  print: {
    success: ".",
    failure: "F",
    error: "R"
  }
}
# This is in a self invoking anonymous lambda so local variables do not
# leak to the outer scope.
-> do
  load_dir = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
  $LOAD_PATH.unshift(load_dir) unless $LOAD_PATH.include?(load_dir)
  require_relative '../lib/dnsruby'
  require_relative 'test_utils'
end.()
