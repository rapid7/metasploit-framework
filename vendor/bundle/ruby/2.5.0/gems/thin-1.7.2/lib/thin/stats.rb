require 'erb'

module Thin
  module Stats
    # Rack adapter to log stats about a Rack application.
    class Adapter
      include ERB::Util
      
      def initialize(app, path='/stats')
        @app  = app
        @path = path

        @template = ERB.new(File.read(File.dirname(__FILE__) + '/stats.html.erb'))
        
        @requests          = 0
        @requests_finished = 0
        @start_time        = Time.now
      end
      
      def call(env)
        if env['PATH_INFO'].index(@path) == 0
          serve(env)
        else
          log(env) { @app.call(env) }
        end
      end
      
      def log(env)
        @requests += 1
        @last_request = Rack::Request.new(env)
        request_started_at = Time.now
        
        response = yield
        
        @requests_finished += 1
        @last_request_time = Time.now - request_started_at
        
        response
      end
      
      def serve(env)
        body = @template.result(binding)
        
        [
          200,
          { 'Content-Type' => 'text/html' },
          [body]
        ]
      end
    end
  end
end
