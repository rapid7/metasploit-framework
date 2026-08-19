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

      # Sinatra 4 / rack-protection 4.x enables host authorization by default;
      # the JSON-RPC service binds to user-specified addresses so all hosts are permitted.
      set :host_authorization, { permitted_hosts: [] }

      set :sessions, {key: 'msf-ws.session', expire_after: 300}
      set :session_secret, ENV.fetch('MSF_WS_SESSION_SECRET', SecureRandom.hex(32))
      set :api_token, ENV.fetch('MSF_WS_JSON_RPC_API_TOKEN', nil)

      # The store used to validate incoming API tokens, not the service's database handle -
      # it stays nil when a static token is configured, even though the framework is still
      # connected to a database and db.* remains available. Populated once by boot! before
      # the server accepts connections, so every request reads it with no DB calls.
      set :db_manager, nil
    end

    # Raised when a usable authentication configuration cannot be established at startup.
    class BootError < StandardError; end

    # Shortest static API token accepted from the environment.
    MIN_API_TOKEN_LENGTH = 16

    # Appended to every BootError so the operator knows both ways out.
    REMEDY = 'Set MSF_WS_JSON_RPC_API_TOKEN to a token of at least ' \
             "#{MIN_API_TOKEN_LENGTH} characters, which needs no database, " \
             "or run 'msfdb init' and create a user to authenticate with database API tokens.".freeze

    # Appended when only the static token route is available.
    REMEDY_TOKEN_ONLY = 'Set MSF_WS_JSON_RPC_API_TOKEN to a token of at least ' \
                        "#{MIN_API_TOKEN_LENGTH} characters.".freeze

    # Appended when the database holds users but none of them have an API token. Creating a
    # user does not issue one - report_user leaves persistence_token unset - so this is a
    # reachable state rather than a theoretical one.
    REMEDY_NO_USER_TOKEN = "Issue one with 'POST /api/v1/auth/generate-token' on the data service, " \
                           'or set MSF_WS_JSON_RPC_API_TOKEN to a token of at least ' \
                           "#{MIN_API_TOKEN_LENGTH} characters instead.".freeze

    # Initialise auth and DB state once at startup.
    # Called from the warmup block in msf-json-rpc.ru, after the framework is
    # ready but before the socket is bound and connections are accepted.
    #
    # A database is not required, but authentication is. It is resolved from either:
    #
    #   1. a static token supplied via MSF_WS_JSON_RPC_API_TOKEN
    #   2. API tokens belonging to users in the database, when it is reachable
    #
    # If neither is available the service refuses to start, rather than accepting
    # unauthenticated requests.
    #
    # Only option 2 needs a database to authenticate against. Which option is in use says
    # nothing about whether a database is connected: the framework connects regardless of
    # the token, so db.* works alongside a static token whenever a database is configured.
    #
    # @raise [BootError] if authentication is not configured usably.
    # @raise [FrameworkExtension::DataServiceError] if a configured data service is unreachable.
    def self.boot!
      # Build the framework up front so that connecting to the database, and any failure
      # doing so, happens here rather than on the first request to reach the service.
      settings.framework

      token = settings.api_token
      unless blank_token?(token)
        if token.length < MIN_API_TOKEN_LENGTH
          raise BootError, 'JSON-RPC server cannot start: MSF_WS_JSON_RPC_API_TOKEN must be at least ' \
                           "#{MIN_API_TOKEN_LENGTH} characters."
        end

        return
      end

      # A blank token would otherwise authenticate any request presenting an equally
      # blank token, so discard it and fall back to database authentication.
      settings.api_token = nil

      # User accounts of a remote data service live on that service, not locally, so its
      # API tokens cannot be validated here. The local database that Active Record requires
      # alongside it holds a different set of users, and authenticating against those would
      # grant access on credentials the operator never issued for this service.
      unless settings.data_service_url.nil? || settings.data_service_url.empty?
        raise BootError, 'JSON-RPC server cannot start: no API token is configured and API tokens cannot ' \
                         "be validated against the remote data service #{settings.data_service_url}. " \
                         "#{REMEDY_TOKEN_ONLY}"
      end

      db = settings.framework.db
      unless db.active
        raise BootError, 'JSON-RPC server cannot start: no API token is configured and the database is ' \
                         "not available. #{REMEDY}"
      end

      begin
        users = db.users({})
        # A nil list means no data service is registered at all, which is indistinguishable
        # here from an empty users table and reported the same way.
        tokens = users.nil? ? [] : users.map(&:persistence_token)
      rescue StandardError => e
        raise BootError, 'JSON-RPC server cannot start: no API token is configured and the database ' \
                         "could not be queried (#{e.class}: #{e.message}). #{REMEDY}"
      end

      if tokens.empty?
        raise BootError, 'JSON-RPC server cannot start: no API token is configured and the database ' \
                         "holds no users. #{REMEDY}"
      end

      # Existing users are not enough: this application only authenticates persistence_token,
      # so a database of password-only accounts would start a service that 401s every request.
      if tokens.all? { |user_token| blank_token?(user_token) }
        raise BootError, 'JSON-RPC server cannot start: no API token is configured and no user in the ' \
                         "database has an API token to authenticate with. #{REMEDY_NO_USER_TOKEN}"
      end

      settings.db_manager = db
    end

    # @return [Boolean] true if the token is missing or contains no usable characters.
    def self.blank_token?(token)
      !token.is_a?(String) || token.strip.empty?
    end

    before do
      request.env['msf.db_manager'] = settings.db_manager if settings.db_manager
      request.env['msf.api_token'] = settings.api_token unless settings.api_token.nil?
      # This application has no unauthenticated bootstrap flow: boot! guarantees either a
      # static token or a database user before connections are accepted, so authentication
      # is always enforced. See Authentication::Strategies::ApiToken#auth_initialized?.
      request.env['msf.auth_initialized'] = true
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

    def self.setup_default_middleware(builder)
      super
      # Insertion at pos 1 needed to immediately follow Sinatra::ExtendedBase
      # proc block identical to one used in 'use' method lib/rack/builder:86
      builder.instance_variable_get(:@use).insert(1, proc { |app| JsonRpcExceptionHandling::RackMiddleware.new(app) })
    end
  end
end
