require 'thread'
require 'rack/body_proxy'

module Rack
  class Lock
    FLAG = 'rack.multithread'.freeze

    def initialize(app, mutex = Mutex.new)
      @app, @mutex = app, mutex
    end

    def call(env)
      old, env[FLAG] = env[FLAG], false
      @mutex.lock
      response = @app.call(env)
      response[2] = BodyProxy.new(response[2]) { @mutex.unlock }
      response
    rescue Exception
      @mutex.unlock
      raise
    ensure
      env[FLAG] = old
    end
  end
end
