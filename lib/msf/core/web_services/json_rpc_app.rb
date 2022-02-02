require 'securerandom'
require 'sinatra/base'
require 'swagger/blocks'
require 'warden'
require 'msf/core/web_services/authentication'
module Msf::WebServices
  class JsonRpcApp < Sinatra::Base

    helpers ServletHelper
    helpers Msf::RPC::JSON::DispatcherHelper

    # Extension registration
    register FrameworkExtension

    # Servlet registration
    register AuthServlet
    register HealthServlet
    register JsonRpcServlet

    # Custom error handling
    register JsonRpcExceptionHandling::SinatraExtension

    configure do
      set :dispatchers, {}

      # Disables Sinatra HTML Error Responses
      set :show_exceptions, false

      set :sessions, {key: 'msf-ws.session', expire_after: 300}
      set :session_secret, ENV.fetch('MSF_WS_SESSION_SECRET', SecureRandom.hex(16))
      set :api_token, ENV.fetch('MSF_WS_JSON_RPC_API_TOKEN', nil)
    end

    before do
      db = get_db
      @@auth_initialized = false
      if db_initialized(db)
        # store DBManager in request environment so that it is available to Warden
        request.env['msf.db_manager'] = db
        @@auth_initialized ||= get_db.users({}).count > 0
      end
      if !settings.api_token.nil?
        @@auth_initialized = true
        request.env['msf.api_token'] = settings.api_token
      end

      # store flag indicating whether authentication is initialized in the request environment
      request.env['msf.auth_initialized'] = @@auth_initialized
    end

    use Warden::Manager do |config|
      # failed authentication is handled by this application
      config.failure_app = self
      # don't intercept 401 responses since the app will provide custom failure messages
      config.intercept_401 = false
      config.default_scope = :api

      config.scope_defaults :user,
                            # whether to persist the result in the session or not
                            store: true,
                            # list of strategies to use
                            strategies: [:password],
                            # action (route) of the failure application
                            action: "#{AuthServlet.api_unauthenticated_path}/user"

      config.scope_defaults :api,
                            # whether to persist the result in the session or not
                            store: false,
                            # list of strategies to use
                            strategies: [:api_token],
                            # action (route) of the failure application
                            action: AuthServlet.api_unauthenticated_path

      config.scope_defaults :admin_api,
                            # whether to persist the result in the session or not
                            store: false,
                            # list of strategies to use
                            strategies: [:admin_api_token],
                            # action (route) of the failure application
                            action: AuthServlet.api_unauthenticated_path
    end

    def db_initialized(db)
      db.check
      true
    rescue
      false
    end

    def self.setup_default_middleware(builder)
      super
      # Insertion at pos 1 needed to immediately follow Sinatra::ExtendedBase
      # proc block identical to one used in 'use' method lib/rack/builder:86
      builder.instance_variable_get(:@use).insert(1, proc { |app| JsonRpcExceptionHandling::RackMiddleware.new(app) })
    end
  end
end
