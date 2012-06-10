require 'logger'

module Rack
  # Sets up rack.logger to write to rack.errors stream
  class Logger
    def initialize(app, level = ::Logger::INFO)
      @app, @level = app, level
    end

    def call(env)
      logger = ::Logger.new(env['rack.errors'])
      logger.level = @level

      env['rack.logger'] = logger
      @app.call(env)
    end
  end
end
