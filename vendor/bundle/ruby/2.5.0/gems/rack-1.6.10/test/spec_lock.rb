require 'rack/lint'
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

module LockHelpers
  def lock_app(app, lock = Lock.new)
    app = if lock
      Rack::Lock.new app, lock
    else
      Rack::Lock.new app
    end
    Rack::Lint.new app
  end
end

describe Rack::Lock do
  extend LockHelpers

  describe 'Proxy' do
    extend LockHelpers

    should 'delegate each' do
      env      = Rack::MockRequest.env_for("/")
      response = Class.new {
        attr_accessor :close_called
        def initialize; @close_called = false; end
        def each; %w{ hi mom }.each { |x| yield x }; end
      }.new

      app = lock_app(lambda { |inner_env| [200, {"Content-Type" => "text/plain"}, response] })
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

      app = Rack::Lock.new(lambda { |inner_env| [200, {"Content-Type" => "text/plain"}, res] }, lock)
      body = app.call(env)[2]

      body.should.respond_to :to_path
      body.to_path.should.equal "/tmp/hello.txt"
    end

    should 'not delegate to_path if body does not implement it' do
      env  = Rack::MockRequest.env_for("/")

      res = ['Hello World']

      app = lock_app(lambda { |inner_env| [200, {"Content-Type" => "text/plain"}, res] })
      body = app.call(env)[2]

      body.should.not.respond_to :to_path
    end
  end

  should 'call super on close' do
    env      = Rack::MockRequest.env_for("/")
    response = Class.new {
      attr_accessor :close_called
      def initialize; @close_called = false; end
      def close; @close_called = true; end
    }.new

    app = lock_app(lambda { |inner_env| [200, {"Content-Type" => "text/plain"}, response] })
    app.call(env)
    response.close_called.should.equal false
    response.close
    response.close_called.should.equal true
  end

  should "not unlock until body is closed" do
    lock     = Lock.new
    env      = Rack::MockRequest.env_for("/")
    response = Object.new
    app      = lock_app(lambda { |inner_env| [200, {"Content-Type" => "text/plain"}, response] }, lock)
    lock.synchronized.should.equal false
    response = app.call(env)[2]
    lock.synchronized.should.equal true
    response.close
    lock.synchronized.should.equal false
  end

  should "return value from app" do
    env  = Rack::MockRequest.env_for("/")
    body = [200, {"Content-Type" => "text/plain"}, %w{ hi mom }]
    app  = lock_app(lambda { |inner_env| body })

    res = app.call(env)
    res[0].should.equal body[0]
    res[1].should.equal body[1]
    res[2].to_enum.to_a.should.equal ["hi", "mom"]
  end

  should "call synchronize on lock" do
    lock = Lock.new
    env = Rack::MockRequest.env_for("/")
    app = lock_app(lambda { |inner_env| [200, {"Content-Type" => "text/plain"}, %w{ a b c }] }, lock)
    lock.synchronized.should.equal false
    app.call(env)
    lock.synchronized.should.equal true
  end

  should "unlock if the app raises" do
    lock = Lock.new
    env = Rack::MockRequest.env_for("/")
    app = lock_app(lambda { raise Exception }, lock)
    lambda { app.call(env) }.should.raise(Exception)
    lock.synchronized.should.equal false
  end

  should "unlock if the app throws" do
    lock = Lock.new
    env = Rack::MockRequest.env_for("/")
    app = lock_app(lambda {|_| throw :bacon }, lock)
    lambda { app.call(env) }.should.throw(:bacon)
    lock.synchronized.should.equal false
  end

  should "set multithread flag to false" do
    app = lock_app(lambda { |env|
      env['rack.multithread'].should.equal false
      [200, {"Content-Type" => "text/plain"}, %w{ a b c }]
    }, false)
    app.call(Rack::MockRequest.env_for("/"))
  end

  should "reset original multithread flag when exiting lock" do
    app = Class.new(Rack::Lock) {
      def call(env)
        env['rack.multithread'].should.equal true
        super
      end
    }.new(lambda { |env| [200, {"Content-Type" => "text/plain"}, %w{ a b c }] })
    Rack::Lint.new(app).call(Rack::MockRequest.env_for("/"))
  end
end
