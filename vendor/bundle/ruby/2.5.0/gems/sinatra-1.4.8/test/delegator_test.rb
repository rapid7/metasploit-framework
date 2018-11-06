require File.expand_path('../helper', __FILE__)

class DelegatorTest < Minitest::Test
  class Mirror
    attr_reader :last_call
    def method_missing(*a, &b)
      @last_call = [*a.map(&:to_s)]
      @last_call << b if b
    end
  end

  def self.delegates(name)
    it "delegates #{name}" do
      m = mirror { send name }
      assert_equal [name.to_s], m.last_call
    end

    it "delegates #{name} with arguments" do
      m = mirror { send name, "foo", "bar" }
      assert_equal [name.to_s, "foo", "bar"], m.last_call
    end

    it "delegates #{name} with block" do
      block = proc { }
      m = mirror { send(name, &block) }
      assert_equal [name.to_s, block], m.last_call
    end
  end

  setup do
    @target_was = Sinatra::Delegator.target
  end

  def teardown
    Sinatra::Delegator.target = @target_was
  end

  def delegation_app(&block)
    mock_app { Sinatra::Delegator.target = self }
    delegate(&block)
  end

  def mirror(&block)
    mirror = Mirror.new
    Sinatra::Delegator.target = mirror
    delegate(&block)
  end

  def delegate(&block)
    assert Sinatra::Delegator.target != Sinatra::Application
    Object.new.extend(Sinatra::Delegator).instance_eval(&block) if block
    Sinatra::Delegator.target
  end

  def target
    Sinatra::Delegator.target
  end

  it 'defaults to Sinatra::Application as target' do
    assert_equal Sinatra::Application, Sinatra::Delegator.target
  end

  %w[get put post delete options patch link unlink].each do |verb|
    it "delegates #{verb} correctly" do
      delegation_app do
        send(verb, '/hello') { 'Hello World' }
      end

      request = Rack::MockRequest.new(@app)
      response = request.request(verb.upcase, '/hello', {})
      assert response.ok?
      assert_equal 'Hello World', response.body
    end
  end

  it "delegates head correctly" do
    delegation_app do
      head '/hello' do
        response['X-Hello'] = 'World!'
        'remove me'
      end
    end

    request = Rack::MockRequest.new(@app)
    response = request.request('HEAD', '/hello', {})
    assert response.ok?
    assert_equal 'World!', response['X-Hello']
    assert_equal '', response.body
  end

  it "registers extensions with the delegation target" do
    app, mixin = mirror, Module.new
    Sinatra.register mixin
    assert_equal ["register", mixin.to_s], app.last_call
  end

  it "registers helpers with the delegation target" do
    app, mixin = mirror, Module.new
    Sinatra.helpers mixin
    assert_equal ["helpers", mixin.to_s], app.last_call
  end

  it "registers middleware with the delegation target" do
    app, mixin = mirror, Module.new
    Sinatra.use mixin
    assert_equal ["use", mixin.to_s], app.last_call
  end

  it "should work with method_missing proxies for options" do
    mixin = Module.new do
      def respond_to?(method, *)
        method.to_sym == :options or super
      end

      def method_missing(method, *args, &block)
        return super unless method.to_sym == :options
        {:some => :option}
      end
    end

    value = nil
    mirror do
      extend mixin
      value = options
    end

    assert_equal({:some => :option}, value)
  end

  it "delegates crazy method names" do
    Sinatra::Delegator.delegate "foo:bar:"
    method = mirror { send "foo:bar:" }.last_call.first
    assert_equal "foo:bar:", method
  end

  delegates 'get'
  delegates 'patch'
  delegates 'put'
  delegates 'post'
  delegates 'delete'
  delegates 'head'
  delegates 'options'
  delegates 'template'
  delegates 'layout'
  delegates 'before'
  delegates 'after'
  delegates 'error'
  delegates 'not_found'
  delegates 'configure'
  delegates 'set'
  delegates 'mime_type'
  delegates 'enable'
  delegates 'disable'
  delegates 'use'
  delegates 'development?'
  delegates 'test?'
  delegates 'production?'
  delegates 'helpers'
  delegates 'settings'
end
