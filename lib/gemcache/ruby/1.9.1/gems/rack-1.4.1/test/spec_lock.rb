require 'rack/lock'
require 'rack/mock'

class Lock
  attr_reader :synchronized

  def initialize
    @synchronized = false
  end

  def synchronize
    @synchronized = true
    yield
  end

  def lock
    @synchronized = true
  end

  def unlock
    @synchronized = false
  end
end

describe Rack::Lock do
  describe 'Proxy' do
    should 'delegate each' do
      lock     = Lock.new
      env      = Rack::MockRequest.env_for("/")
      response = Class.new {
        attr_accessor :close_called
        def initialize; @close_called = false; end
        def each; %w{ hi mom }.each { |x| yield x }; end
      }.new

      app = Rack::Lock.new(lambda { |inner_env| [200, {}, response] }, lock)
      response = app.call(env)[2]
      list = []
      response.each { |x| list << x }
      list.should.equal %w{ hi mom }
    end

    should 'delegate to_path' do
      lock = Lock.new
      env  = Rack::MockRequest.env_for("/")

      res = ['Hello World']
      def res.to_path ; "/tmp/hello.txt" ; end

      app = Rack::Lock.new(lambda { |inner_env| [200, {}, res] }, lock)
      body = app.call(env)[2]

      body.should.respond_to :to_path
      body.to_path.should.equal "/tmp/hello.txt"
    end

    should 'not delegate to_path if body does not implement it' do
      lock = Lock.new
      env  = Rack::MockRequest.env_for("/")

      res = ['Hello World']

      app = Rack::Lock.new(lambda { |inner_env| [200, {}, res] }, lock)
      body = app.call(env)[2]

      body.should.not.respond_to :to_path
    end
  end

  should 'call super on close' do
    lock     = Lock.new
    env      = Rack::MockRequest.env_for("/")
    response = Class.new {
      attr_accessor :close_called
      def initialize; @close_called = false; end
      def close; @close_called = true; end
    }.new

    app = Rack::Lock.new(lambda { |inner_env| [200, {}, response] }, lock)
    app.call(env)
    response.close_called.should.equal false
    response.close
    response.close_called.should.equal true
  end

  should "not unlock until body is closed" do
    lock     = Lock.new
    env      = Rack::MockRequest.env_for("/")
    response = Object.new
    app      = Rack::Lock.new(lambda { |inner_env| [200, {}, response] }, lock)
    lock.synchronized.should.equal false
    response = app.call(env)[2]
    lock.synchronized.should.equal true
    response.close
    lock.synchronized.should.equal false
  end

  should "return value from app" do
    lock = Lock.new
    env  = Rack::MockRequest.env_for("/")
    body = [200, {}, %w{ hi mom }]
    app  = Rack::Lock.new(lambda { |inner_env| body }, lock)
    app.call(env).should.equal body
  end

  should "call synchronize on lock" do
    lock = Lock.new
    env = Rack::MockRequest.env_for("/")
    app = Rack::Lock.new(lambda { |inner_env|
      [200, {}, %w{ a b c }]
    }, lock)
    lock.synchronized.should.equal false
    app.call(env)
    lock.synchronized.should.equal true
  end

  should "unlock if the app raises" do
    lock = Lock.new
    env = Rack::MockRequest.env_for("/")
    app = Rack::Lock.new(lambda { raise Exception }, lock)
    lambda { app.call(env) }.should.raise(Exception)
    lock.synchronized.should.equal false
  end

  should "set multithread flag to false" do
    app = Rack::Lock.new(lambda { |env|
      env['rack.multithread'].should.equal false
      [200, {}, %w{ a b c }]
    })
    app.call(Rack::MockRequest.env_for("/"))
  end

  should "reset original multithread flag when exiting lock" do
    app = Class.new(Rack::Lock) {
      def call(env)
        env['rack.multithread'].should.equal true
        super
      end
    }.new(lambda { |env| [200, {}, %w{ a b c }] })
    app.call(Rack::MockRequest.env_for("/"))
  end
end
