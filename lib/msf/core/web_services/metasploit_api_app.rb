require 'securerandom'
require 'sinatra/base'
require 'swagger/blocks'
require 'warden'
require 'msf/core/web_services/authentication'
class Msf::WebServices::MetasploitApiApp < Sinatra::Base
  helpers Msf::WebServices::ServletHelper

  # Servlet registration
  register Msf::WebServices::ApiDocsServlet
  register Msf::WebServices::AuthServlet
  register Msf::WebServices::HostServlet
  register Msf::WebServices::VulnServlet
  register Msf::WebServices::EventServlet
  register Msf::WebServices::WebServlet
  register Msf::WebServices::MsfServlet
  register Msf::WebServices::NoteServlet
  register Msf::WebServices::WorkspaceServlet
  register Msf::WebServices::ServiceServlet
  register Msf::WebServices::SessionServlet
  register Msf::WebServices::ExploitServlet
  register Msf::WebServices::LootServlet
  register Msf::WebServices::SessionEventServlet
  register Msf::WebServices::CredentialServlet
  register Msf::WebServices::LoginServlet
  register Msf::WebServices::NmapServlet
  register Msf::WebServices::DbExportServlet
  register Msf::WebServices::VulnAttemptServlet
  register Msf::WebServices::UserServlet
  register Msf::WebServices::PayloadServlet
  register Msf::WebServices::ModuleSearchServlet
  register Msf::WebServices::DbImportServlet
  register Msf::WebServices::RouteServlet

  configure do
    set :sessions, {key: 'msf-ws.session', expire_after: 300}
    set :session_secret, ENV.fetch('MSF_WS_SESSION_SECRET') { SecureRandom.hex(32) }
    # Sinatra 4 / rack-protection 4.x enables host authorization by default;
    # the web service binds to user-specified addresses so all hosts are permitted.
    set :host_authorization, { permitted_hosts: [] }
  end

  before do
    # store DBManager in request environment so that it is available to Warden
    request.env['msf.db_manager'] = get_db
    # Once a user exists the flag latches on for the lifetime of the process.
    @@auth_initialized ||= get_db.users({}).count > 0
    # While no users exist an initial account has to be creatable before any credentials
    # exist - msfdb relies on this to POST the first user to /api/v1/users. The exemption is
    # limited to that one route, so a database that reports no users for any other reason -
    # an empty database restored under the service, a failover onto a fresh instance - cannot
    # expose the rest of the API unauthenticated.
    request.env['msf.auth_initialized'] = @@auth_initialized || !initial_account_creation?
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
                          action: "#{Msf::WebServices::AuthServlet.api_unauthenticated_path}/user"

    config.scope_defaults :api,
                          # whether to persist the result in the session or not
                          store: false,
                          # list of strategies to use
                          strategies: [:api_token],
                          # action (route) of the failure application
                          action: Msf::WebServices::AuthServlet.api_unauthenticated_path

    config.scope_defaults :admin_api,
                          # whether to persist the result in the session or not
                          store: false,
                          # list of strategies to use
                          strategies: [:admin_api_token],
                          # action (route) of the failure application
                          action: Msf::WebServices::AuthServlet.api_unauthenticated_path
  end

  # Whether the request is the one that creates a user account, which is the only request
  # permitted to run unauthenticated before any account exists.
  #
  # @return [Boolean] true if the request creates a user account; otherwise, false.
  def initial_account_creation?
    request.post? && request.path_info.chomp('/') == Msf::WebServices::UserServlet.api_path
  end

end
