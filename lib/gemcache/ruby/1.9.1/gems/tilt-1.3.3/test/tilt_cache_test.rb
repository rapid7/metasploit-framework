require 'contest'
require 'tilt'

class TiltCacheTest < Test::Unit::TestCase
  setup { @cache = Tilt::Cache.new }

  test "caching with single simple argument to #fetch" do
    template = nil
    result = @cache.fetch('hello') { template = Tilt::StringTemplate.new {''} }
    assert_same template, result
    result = @cache.fetch('hello') { fail 'should be cached' }
    assert_same template, result
  end

  test "caching with multiple complex arguments to #fetch" do
    template = nil
    result = @cache.fetch('hello', {:foo => 'bar', :baz => 'bizzle'}) { template = Tilt::StringTemplate.new {''} }
    assert_same template, result
    result = @cache.fetch('hello', {:foo => 'bar', :baz => 'bizzle'}) { fail 'should be cached' }
    assert_same template, result
  end

  test "clearing the cache with #clear" do
    template, other = nil
    result = @cache.fetch('hello') { template = Tilt::StringTemplate.new {''} }
    assert_same template, result

    @cache.clear
    result = @cache.fetch('hello') { other = Tilt::StringTemplate.new {''} }
    assert_same other, result
  end
end
