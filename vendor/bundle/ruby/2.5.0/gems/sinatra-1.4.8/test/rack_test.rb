require File.expand_path('../helper', __FILE__)
require 'rack'

class RackTest < Minitest::Test
  setup do
    @foo = Sinatra.new { get('/foo') { 'foo' }}
    @bar = Sinatra.new { get('/bar') { 'bar' }}
  end

  def build(*middleware)
    endpoint = middleware.pop
    @app = Rack::Builder.app do
      middleware.each { |m| use m }
      run endpoint
    end
  end

  def check(*middleware)
    build(*middleware)
    assert get('/foo').ok?
    assert_body 'foo'
    assert get('/bar').ok?
    assert_body 'bar'
  end

  it 'works as middleware in front of Rack::Lock, with lock enabled' do
    @foo.enable :lock
    check(@foo, Rack::Lock, @bar)
  end

  it 'works as middleware behind Rack::Lock, with lock enabled' do
    @foo.enable :lock
    check(Rack::Lock, @foo, @bar)
  end

  it 'works as middleware in front of Rack::Lock, with lock disabled' do
    @foo.disable :lock
    check(@foo, Rack::Lock, @bar)
  end

  it 'works as middleware behind Rack::Lock, with lock disabled' do
    @foo.disable :lock
    check(Rack::Lock, @foo, @bar)
  end
end
