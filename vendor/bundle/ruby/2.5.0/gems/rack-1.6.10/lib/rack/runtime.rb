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

    FORMAT_STRING = "%0.6f"
    def call(env)
      start_time = clock_time
      status, headers, body = @app.call(env)
      request_time = clock_time - start_time

      if !headers.has_key?(@header_name)
        headers[@header_name] = FORMAT_STRING % request_time
      end

      [status, headers, body]
    end

    private

    if defined?(Process::CLOCK_MONOTONIC)
      def clock_time
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    else
      def clock_time
        Time.now.to_f
      end
    end
  end
end
