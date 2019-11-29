require 'msf/core/rpc'

module Msf::WebServices
  module JsonRpcServlet

    def self.api_path
      '/api/:version/json-rpc'
    end

    def self.registered(app)
      app.post JsonRpcServlet.api_path, &post_rpc
    end

    #######
    private
    #######

    # Process JSON-RPC request
    def self.post_rpc
      lambda {
        warden.authenticate!
        begin
          body = request.body.read
          tmp_params = sanitize_params(params)
          data = get_dispatcher(settings.dispatchers, tmp_params[:version].to_sym, framework).process(body)
          set_raw_response(data)
        rescue => e
          print_error("There was an error executing the RPC: #{e.message}.", e)
          error = Msf::RPC::JSON::Dispatcher.create_error_response(Msf::RPC::JSON::InternalError.new(e))
          data = Msf::RPC::JSON::Dispatcher.to_json(error)
          set_raw_response(data, code: 500)
        end
      }
    end
  end
end