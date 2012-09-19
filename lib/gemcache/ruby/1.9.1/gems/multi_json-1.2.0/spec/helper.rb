def jruby?
  defined?(RUBY_ENGINE) && RUBY_ENGINE == 'jruby'
end

def macruby?
  defined?(RUBY_ENGINE) && RUBY_ENGINE == 'macruby'
end

unless ENV['CI'] || macruby?
  require 'simplecov'
  SimpleCov.start
end
require 'multi_json'
require 'rspec'

class MockDecoder
  def self.decode(string, options = {})
    {'abc' => 'def'}
  end

  def self.encode(string)
    '{"abc":"def"}'
  end
end

class TimeWithZone
  def to_json(options = {})
    "\"2005-02-01T15:15:10Z\""
  end
end
