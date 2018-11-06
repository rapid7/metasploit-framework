require 'rack/static'
require 'rack/lint'
require 'rack/mock'

class DummyApp
  def call(env)
    [200, {"Content-Type" => "text/plain"}, ["Hello World"]]
  end
end

describe Rack::Static do
  def static(app, *args)
    Rack::Lint.new Rack::Static.new(app, *args)
  end

  root = File.expand_path(File.dirname(__FILE__))

  OPTIONS = {:urls => ["/cgi"], :root => root}
  STATIC_OPTIONS = {:urls => [""], :root => "#{root}/static", :index => 'index.html'}
  HASH_OPTIONS = {:urls => {"/cgi/sekret" => 'cgi/test'}, :root => root}

  @request = Rack::MockRequest.new(static(DummyApp.new, OPTIONS))
  @static_request = Rack::MockRequest.new(static(DummyApp.new, STATIC_OPTIONS))
  @hash_request = Rack::MockRequest.new(static(DummyApp.new, HASH_OPTIONS))

  it "serves files" do
    res = @request.get("/cgi/test")
    res.should.be.ok
    res.body.should =~ /ruby/
  end

  it "404s if url root is known but it can't find the file" do
    res = @request.get("/cgi/foo")
    res.should.be.not_found
  end

  it "calls down the chain if url root is not known" do
    res = @request.get("/something/else")
    res.should.be.ok
    res.body.should == "Hello World"
  end

  it "calls index file when requesting root in the given folder" do
    res = @static_request.get("/")
    res.should.be.ok
    res.body.should =~ /index!/

    res = @static_request.get("/other/")
    res.should.be.not_found

    res = @static_request.get("/another/")
    res.should.be.ok
    res.body.should =~ /another index!/
  end

  it "doesn't call index file if :index option was omitted" do
    res = @request.get("/")
    res.body.should == "Hello World"
  end

  it "serves hidden files" do
    res = @hash_request.get("/cgi/sekret")
    res.should.be.ok
    res.body.should =~ /ruby/
  end

  it "calls down the chain if the URI is not specified" do
    res = @hash_request.get("/something/else")
    res.should.be.ok
    res.body.should == "Hello World"
  end

  it "supports serving fixed cache-control (legacy option)" do
    opts = OPTIONS.merge(:cache_control => 'public')
    request = Rack::MockRequest.new(static(DummyApp.new, opts))
    res = request.get("/cgi/test")
    res.should.be.ok
    res.headers['Cache-Control'].should == 'public'
  end

  HEADER_OPTIONS = {:urls => ["/cgi"], :root => root, :header_rules => [
    [:all, {'Cache-Control' => 'public, max-age=100'}],
    [:fonts, {'Cache-Control' => 'public, max-age=200'}],
    [%w(png jpg), {'Cache-Control' => 'public, max-age=300'}],
    ['/cgi/assets/folder/', {'Cache-Control' => 'public, max-age=400'}],
    ['cgi/assets/javascripts', {'Cache-Control' => 'public, max-age=500'}],
    [/\.(css|erb)\z/, {'Cache-Control' => 'public, max-age=600'}]
  ]}
  @header_request = Rack::MockRequest.new(static(DummyApp.new, HEADER_OPTIONS))

  it "supports header rule :all" do
    # Headers for all files via :all shortcut
    res = @header_request.get('/cgi/assets/index.html')
    res.should.be.ok
    res.headers['Cache-Control'].should == 'public, max-age=100'
  end

  it "supports header rule :fonts" do
    # Headers for web fonts via :fonts shortcut
    res = @header_request.get('/cgi/assets/fonts/font.eot')
    res.should.be.ok
    res.headers['Cache-Control'].should == 'public, max-age=200'
  end

  it "supports file extension header rules provided as an Array" do
    # Headers for file extensions via array
    res = @header_request.get('/cgi/assets/images/image.png')
    res.should.be.ok
    res.headers['Cache-Control'].should == 'public, max-age=300'
  end

  it "supports folder rules provided as a String" do
    # Headers for files in folder via string
    res = @header_request.get('/cgi/assets/folder/test.js')
    res.should.be.ok
    res.headers['Cache-Control'].should == 'public, max-age=400'
  end

  it "supports folder header rules provided as a String not starting with a slash" do
    res = @header_request.get('/cgi/assets/javascripts/app.js')
    res.should.be.ok
    res.headers['Cache-Control'].should == 'public, max-age=500'
  end

  it "supports flexible header rules provided as Regexp" do
    # Flexible Headers via Regexp
    res = @header_request.get('/cgi/assets/stylesheets/app.css')
    res.should.be.ok
    res.headers['Cache-Control'].should == 'public, max-age=600'
  end

  it "prioritizes header rules over fixed cache-control setting (legacy option)" do
    opts = OPTIONS.merge(
      :cache_control => 'public, max-age=24',
      :header_rules => [
        [:all, {'Cache-Control' => 'public, max-age=42'}]
      ])

    request = Rack::MockRequest.new(static(DummyApp.new, opts))
    res = request.get("/cgi/test")
    res.should.be.ok
    res.headers['Cache-Control'].should == 'public, max-age=42'
  end

end
