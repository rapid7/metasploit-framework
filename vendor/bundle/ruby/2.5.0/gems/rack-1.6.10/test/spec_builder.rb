require 'rack/builder'
require 'rack/lint'
require 'rack/mock'
require 'rack/showexceptions'
require 'rack/urlmap'

class NothingMiddleware
  def initialize(app)
    @app = app
  end
  def call(env)
    @@env = env
    response = @app.call(env)
    response
  end
  def self.env
    @@env
  end
end

describe Rack::Builder do
  def builder(&block)
    Rack::Lint.new Rack::Builder.new(&block)
  end
  
  def builder_to_app(&block)
    Rack::Lint.new Rack::Builder.new(&block).to_app
  end
  
  it "supports mapping" do
    app = builder_to_app do
      map '/' do |outer_env|
        run lambda { |inner_env| [200, {"Content-Type" => "text/plain"}, ['root']] }
      end
      map '/sub' do
        run lambda { |inner_env| [200, {"Content-Type" => "text/plain"}, ['sub']] }
      end
    end
    Rack::MockRequest.new(app).get("/").body.to_s.should.equal 'root'
    Rack::MockRequest.new(app).get("/sub").body.to_s.should.equal 'sub'
  end

  it "doesn't dupe env even when mapping" do
    app = builder_to_app do
      use NothingMiddleware
      map '/' do |outer_env|
        run lambda { |inner_env|
          inner_env['new_key'] = 'new_value'
          [200, {"Content-Type" => "text/plain"}, ['root']]
        }
      end
    end
    Rack::MockRequest.new(app).get("/").body.to_s.should.equal 'root'
    NothingMiddleware.env['new_key'].should.equal 'new_value'
  end

  it "chains apps by default" do
    app = builder_to_app do
      use Rack::ShowExceptions
      run lambda { |env| raise "bzzzt" }
    end

    Rack::MockRequest.new(app).get("/").should.be.server_error
    Rack::MockRequest.new(app).get("/").should.be.server_error
    Rack::MockRequest.new(app).get("/").should.be.server_error
  end

  it "has implicit #to_app" do
    app = builder do
      use Rack::ShowExceptions
      run lambda { |env| raise "bzzzt" }
    end

    Rack::MockRequest.new(app).get("/").should.be.server_error
    Rack::MockRequest.new(app).get("/").should.be.server_error
    Rack::MockRequest.new(app).get("/").should.be.server_error
  end

  it "supports blocks on use" do
    app = builder do
      use Rack::ShowExceptions
      use Rack::Auth::Basic do |username, password|
        'secret' == password
      end

      run lambda { |env| [200, {"Content-Type" => "text/plain"}, ['Hi Boss']] }
    end

    response = Rack::MockRequest.new(app).get("/")
    response.should.be.client_error
    response.status.should.equal 401

    # with auth...
    response = Rack::MockRequest.new(app).get("/",
        'HTTP_AUTHORIZATION' => 'Basic ' + ["joe:secret"].pack("m*"))
    response.status.should.equal 200
    response.body.to_s.should.equal 'Hi Boss'
  end

  it "has explicit #to_app" do
    app = builder do
      use Rack::ShowExceptions
      run lambda { |env| raise "bzzzt" }
    end

    Rack::MockRequest.new(app).get("/").should.be.server_error
    Rack::MockRequest.new(app).get("/").should.be.server_error
    Rack::MockRequest.new(app).get("/").should.be.server_error
  end

  it "can mix map and run for endpoints" do
    app = builder do
      map '/sub' do
        run lambda { |inner_env| [200, {"Content-Type" => "text/plain"}, ['sub']] }
      end
      run lambda { |inner_env| [200, {"Content-Type" => "text/plain"}, ['root']] }
    end

    Rack::MockRequest.new(app).get("/").body.to_s.should.equal 'root'
    Rack::MockRequest.new(app).get("/sub").body.to_s.should.equal 'sub'
  end

  it "accepts middleware-only map blocks" do
    app = builder do
      map('/foo') { use Rack::ShowExceptions }
      run lambda { |env| raise "bzzzt" }
    end

    proc { Rack::MockRequest.new(app).get("/") }.should.raise(RuntimeError)
    Rack::MockRequest.new(app).get("/foo").should.be.server_error
  end

  it "yields the generated app to a block for warmup" do
    warmed_up_app = nil

    app = Rack::Builder.new do
      warmup { |a| warmed_up_app = a }
      run lambda { |env| [200, {}, []] }
    end.to_app

    warmed_up_app.should.equal app
  end

  should "initialize apps once" do
    app = builder do
      class AppClass
        def initialize
          @called = 0
        end
        def call(env)
          raise "bzzzt"  if @called > 0
        @called += 1
          [200, {'Content-Type' => 'text/plain'}, ['OK']]
        end
      end

      use Rack::ShowExceptions
      run AppClass.new
    end

    Rack::MockRequest.new(app).get("/").status.should.equal 200
    Rack::MockRequest.new(app).get("/").should.be.server_error
  end

  it "allows use after run" do
    app = builder do
      run lambda { |env| raise "bzzzt" }
      use Rack::ShowExceptions
    end

    Rack::MockRequest.new(app).get("/").should.be.server_error
    Rack::MockRequest.new(app).get("/").should.be.server_error
    Rack::MockRequest.new(app).get("/").should.be.server_error
  end

  it 'complains about a missing run' do
    proc do
      Rack::Lint.new Rack::Builder.app { use Rack::ShowExceptions }
    end.should.raise(RuntimeError)
  end

  describe "parse_file" do
    def config_file(name)
      File.join(File.dirname(__FILE__), 'builder', name)
    end

    it "parses commented options" do
      app, options = Rack::Builder.parse_file config_file('options.ru')
      options[:debug].should.be.true
      Rack::MockRequest.new(app).get("/").body.to_s.should.equal 'OK'
    end

    it "removes __END__ before evaluating app" do
      app, _ = Rack::Builder.parse_file config_file('end.ru')
      Rack::MockRequest.new(app).get("/").body.to_s.should.equal 'OK'
    end

    it "supports multi-line comments" do
      lambda {
        Rack::Builder.parse_file config_file('comment.ru')
      }.should.not.raise(SyntaxError)
    end

    it "requires anything not ending in .ru" do
      $: << File.dirname(__FILE__)
      app, * = Rack::Builder.parse_file 'builder/anything'
      Rack::MockRequest.new(app).get("/").body.to_s.should.equal 'OK'
      $:.pop
    end

    it "sets __LINE__ correctly" do
      app, _ = Rack::Builder.parse_file config_file('line.ru')
      Rack::MockRequest.new(app).get("/").body.to_s.should.equal '1'
    end
  end

  describe 'new_from_string' do
    it "builds a rack app from string" do
      app, = Rack::Builder.new_from_string "run lambda{|env| [200, {'Content-Type' => 'text/plane'}, ['OK']] }"
      Rack::MockRequest.new(app).get("/").body.to_s.should.equal 'OK'
    end
  end
end
