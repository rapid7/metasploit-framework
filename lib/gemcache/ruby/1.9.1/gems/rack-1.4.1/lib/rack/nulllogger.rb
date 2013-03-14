module Rack
  class NullLogger
    def initialize(app)
      @app = app
    end

    def call(env)
      env['rack.logger'] = self
      @app.call(env)
    end

    def info(progname = nil, &block);  end
    def debug(progname = nil, &block); end
    def warn(progname = nil, &block);  end
    def error(progname = nil, &block); end
    def fatal(progname = nil, &block); end
  end
end
