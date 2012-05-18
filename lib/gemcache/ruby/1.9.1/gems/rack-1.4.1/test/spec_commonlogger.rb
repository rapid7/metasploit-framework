require 'rack/commonlogger'
require 'rack/lint'
require 'rack/mock'

describe Rack::CommonLogger do
  obj = 'foobar'
  length = obj.size

  app = Rack::Lint.new lambda { |env|
    [200,
     {"Content-Type" => "text/html", "Content-Length" => length.to_s},
     [obj]]}
  app_without_length = Rack::Lint.new lambda { |env|
    [200,
     {"Content-Type" => "text/html"},
     []]}
  app_with_zero_length = Rack::Lint.new lambda { |env|
    [200,
     {"Content-Type" => "text/html", "Content-Length" => "0"},
     []]}

  should "log to rack.errors by default" do
    res = Rack::MockRequest.new(Rack::CommonLogger.new(app)).get("/")

    res.errors.should.not.be.empty
    res.errors.should =~ /"GET \/ " 200 #{length} /
  end

  should "log to anything with +write+" do
    log = StringIO.new
    Rack::MockRequest.new(Rack::CommonLogger.new(app, log)).get("/")

    log.string.should =~ /"GET \/ " 200 #{length} /
  end

  should "log - content length if header is missing" do
    res = Rack::MockRequest.new(Rack::CommonLogger.new(app_without_length)).get("/")

    res.errors.should.not.be.empty
    res.errors.should =~ /"GET \/ " 200 - /
  end

  should "log - content length if header is zero" do
    res = Rack::MockRequest.new(Rack::CommonLogger.new(app_with_zero_length)).get("/")

    res.errors.should.not.be.empty
    res.errors.should =~ /"GET \/ " 200 - /
  end

  def length
    123
  end

  def self.obj
    "hello world"
  end
end
