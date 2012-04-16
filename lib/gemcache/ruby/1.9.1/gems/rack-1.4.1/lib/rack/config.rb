module Rack
  # Rack::Config modifies the environment using the block given during
  # initialization.
  class Config
    def initialize(app, &block)
      @app = app
      @block = block
    end

    def call(env)
      @block.call(env)
      @app.call(env)
    end
  end
end
