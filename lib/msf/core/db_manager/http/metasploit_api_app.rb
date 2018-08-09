require 'sinatra/base'
require 'swagger/blocks'
require 'sysrandom/securerandom'
require 'warden'
require 'msf/core/db_manager/http/authentication'
require 'msf/core/db_manager/http/servlet_helper'
require 'msf/core/db_manager/http/servlet/api_docs_servlet'
require 'msf/core/db_manager/http/servlet/auth_servlet'
require 'msf/core/db_manager/http/servlet/host_servlet'
require 'msf/core/db_manager/http/servlet/note_servlet'
require 'msf/core/db_manager/http/servlet/vuln_servlet'
require 'msf/core/db_manager/http/servlet/event_servlet'
require 'msf/core/db_manager/http/servlet/web_servlet'
require 'msf/core/db_manager/http/servlet/msf_servlet'
require 'msf/core/db_manager/http/servlet/workspace_servlet'
require 'msf/core/db_manager/http/servlet/service_servlet'
require 'msf/core/db_manager/http/servlet/session_servlet'
require 'msf/core/db_manager/http/servlet/exploit_servlet'
require 'msf/core/db_manager/http/servlet/loot_servlet'
require 'msf/core/db_manager/http/servlet/session_event_servlet'
require 'msf/core/db_manager/http/servlet/credential_servlet'
require 'msf/core/db_manager/http/servlet/login_servlet'
require 'msf/core/db_manager/http/servlet/nmap_servlet'
require 'msf/core/db_manager/http/servlet/db_export_servlet'
require 'msf/core/db_manager/http/servlet/vuln_attempt_servlet'
require 'msf/core/db_manager/http/servlet/user_servlet'
require 'msf/core/web_services/servlet/module_search_servlet'

class MetasploitApiApp < Sinatra::Base
  helpers ServletHelper

  # Servlet registration
  register ApiDocsServlet
  register AuthServlet
  register HostServlet
  register VulnServlet
  register EventServlet
  register WebServlet
  register MsfServlet
  register NoteServlet
  register WorkspaceServlet
  register ServiceServlet
  register SessionServlet
  register ExploitServlet
  register LootServlet
  register SessionEventServlet
  register CredentialServlet
  register LoginServlet
  register NmapServlet
  register DbExportServlet
  register VulnAttemptServlet
  register UserServlet
  register ModuleSearchServlet

  configure do
    set :sessions, {key: 'msf-ws.session', expire_after: 300}
    set :session_secret, ENV.fetch('MSF_WS_SESSION_SECRET') { SecureRandom.hex(16) }
  end

  before do
    # store DBManager in request environment so that it is available to Warden
    request.env['msf.db_manager'] = get_db
    # store flag indicating whether authentication is initialized in the request environment
    @@auth_initialized ||= get_db.users({}).count > 0
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

end