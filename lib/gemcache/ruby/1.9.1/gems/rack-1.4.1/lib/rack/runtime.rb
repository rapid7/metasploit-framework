module Rack
  # Sets an "X-Runtime" response header, indicating the response
  # time of the request, in seconds
  #
  # You can put it right before the application to see the processing
  # time, or before all the other middlewares to include time for them,
  # too.
  class Runtime
    def initialize(app, name = nil)
      @app = app
      @header_name = "X-Runtime"
      @header_name << "-#{name}" if name
    end

    def call(env)
      start_time = Time.now
      status, headers, body = @app.call(env)
      request_time = Time.now - start_time

      if !headers.has_key?(@header_name)
        headers[@header_name] = "%0.6f" % request_time
      end

      [status, headers, body]
    end
  end
end
