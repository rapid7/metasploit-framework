require 'sinatra/base'
require 'msf/core/db_manager/http/servlet_helper'
require 'msf/core/db_manager/http/servlet/api_docs_servlet'
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
require 'msf/core/db_manager/http/servlet/nmap_servlet'
require 'msf/core/db_manager/http/servlet/db_export_servlet'
require 'msf/core/db_manager/http/servlet/vuln_attempt_servlet'

require 'swagger/blocks'

class SinatraApp < Sinatra::Base
  set :public_folder, File.dirname(__FILE__) + '/public'

  def root_path
    uri = URI(request.url)
    "#{uri.scheme}://#{uri.host}:#{uri.port}"
  end

  helpers ServletHelper

  # Servlet registration
  register ApiDocsServlet
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
  register NmapServlet
  register DbExportServlet
  register VulnAttemptServlet
end