
module Msf::WebServices::JsonRpcExceptionHandling
  class RackMiddleware
    def initialize(app)
      @app = app
    end

    def call(env)
      begin
        @app.call(env)
      rescue Exception => e
        req = Rack::Request.new(env)
        ErrorHandler.get_response(e, req)
      end
    end
  end

  module SinatraExtension
    def self.registered(app)
      app.error do |err|
        ErrorHandler.get_response(err, self.request)
      end
    end
  end

  class ErrorHandler
    class << self
      def get_response(err, request)
        parsed_request = parse_request(request)
        data = get_data(err)

        response = Msf::RPC::JSON::Dispatcher::create_error_response(
          Msf::RPC::JSON::ApplicationServerError.new(
            err,
            data: data
          ),
          parsed_request
        )

        Rack::Response.new(
          response.to_json,
          500,
          {'Content-type' => 'application/json'}
        ).finish
      end

      private

      def get_data(err)
        return nil unless development?

        {
          "backtrace" => err.backtrace
        }
      end

      def parse_request(req)
        begin
          body = req.body.tap(&:rewind).read
          JSON.parse(body, symbolize_names: true)
        rescue JSON::ParserError
          nil
        end
      end

      def development?
        environment == :development
      end

      def environment
        (ENV['RACK_ENV'] || :development).to_sym
      end
    end
  end
end
