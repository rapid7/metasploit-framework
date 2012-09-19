['..', '../../lib'].each do |path|
  $:.unshift dir if dir = File.expand_path(path, __FILE__) and not $:.include?(dir)
end

require 'simplecov'
SimpleCov.start

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


def yajl_on_travis(engine)
  ENV['TRAVIS'] && engine == 'yajl' && jruby?
end

def jruby?
  defined?(RUBY_ENGINE) && RUBY_ENGINE == 'jruby'
end