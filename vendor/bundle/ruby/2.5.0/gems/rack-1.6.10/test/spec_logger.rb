require 'stringio'
require 'rack/lint'
require 'rack/logger'
require 'rack/mock'

describe Rack::Logger do
  app = lambda { |env|
    log = env['rack.logger']
    log.debug("Created logger")
    log.info("Program started")
    log.warn("Nothing to do!")

    [200, {'Content-Type' => 'text/plain'}, ["Hello, World!"]]
  }

  should "conform to Rack::Lint" do
    errors = StringIO.new
    a = Rack::Lint.new(Rack::Logger.new(app))
    Rack::MockRequest.new(a).get('/', 'rack.errors' => errors)
    errors.string.should.match(/INFO -- : Program started/)
    errors.string.should.match(/WARN -- : Nothing to do/)
  end
end
