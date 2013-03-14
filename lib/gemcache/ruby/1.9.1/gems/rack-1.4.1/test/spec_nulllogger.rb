require 'rack/nulllogger'

describe Rack::NullLogger do
  should "act as a noop logger" do
    app = lambda { |env|
      env['rack.logger'].warn "b00m"
      [200, {'Content-Type' => 'text/plain'}, ["Hello, World!"]]
    }
    logger = Rack::NullLogger.new(app)
    lambda{ logger.call({}) }.should.not.raise
  end
end
