require File.expand_path('../helper', __FILE__)

class MiddlewareTest < Minitest::Test
  setup do
    @app = mock_app(Sinatra::Application) do
      get('/*')do
        response.headers['X-Tests'] = env['test.ran'].
          map { |n| n.split('::').last }.
          join(', ')
        env['PATH_INFO']
      end
    end
  end

  class MockMiddleware < Struct.new(:app)
    def call(env)
      (env['test.ran'] ||= []) << self.class.to_s
      app.call(env)
    end
  end

  class UpcaseMiddleware < MockMiddleware
    def call(env)
      env['PATH_INFO'] = env['PATH_INFO'].upcase
      super
    end
  end

  it "is added with Sinatra::Application.use" do
    @app.use UpcaseMiddleware
    get '/hello-world'
    assert ok?
    assert_equal '/HELLO-WORLD', body
  end

  class DowncaseMiddleware < MockMiddleware
    def call(env)
      env['PATH_INFO'] = env['PATH_INFO'].downcase
      super
    end
  end

  it "runs in the order defined" do
    @app.use UpcaseMiddleware
    @app.use DowncaseMiddleware
    get '/Foo'
    assert_equal "/foo", body
    assert_equal "UpcaseMiddleware, DowncaseMiddleware", response['X-Tests']
  end

  it "resets the prebuilt pipeline when new middleware is added" do
    @app.use UpcaseMiddleware
    get '/Foo'
    assert_equal "/FOO", body
    @app.use DowncaseMiddleware
    get '/Foo'
    assert_equal '/foo', body
    assert_equal "UpcaseMiddleware, DowncaseMiddleware", response['X-Tests']
  end

  it "works when app is used as middleware" do
    @app.use UpcaseMiddleware
    @app = @app.new
    get '/Foo'
    assert_equal "/FOO", body
    assert_equal "UpcaseMiddleware", response['X-Tests']
  end
end
