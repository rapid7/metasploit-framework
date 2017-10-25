require 'sinatra/base'
require 'msf/core/db_manager/http/servlet_helper'
require 'msf/core/db_manager/http/aws/sns_handler'
require 'msf/core/db_manager/http/servlet/host_servlet'
require 'msf/core/db_manager/http/servlet/note_servlet'
require 'msf/core/db_manager/http/servlet/vuln_servlet'
require 'msf/core/db_manager/http/servlet/event_servlet'
require 'msf/core/db_manager/http/servlet/web_servlet'
require 'msf/core/db_manager/http/servlet/online_test_servlet'
require 'msf/core/db_manager/http/servlet/workspace_servlet'
require 'msf/core/db_manager/http/servlet/service_servlet'
require 'msf/core/db_manager/http/servlet/session_servlet'
require 'msf/core/db_manager/http/servlet/exploit_servlet'
require 'msf/core/db_manager/http/servlet/loot_servlet'
require 'msf/core/db_manager/http/servlet/session_event_servlet'
require 'msf/core/db_manager/http/servlet/credential_servlet'
require 'msf/core/db_manager/http/servlet/nmap_servlet'

class SinatraApp < Sinatra::Base

  use SNSHandler

  helpers ServletHelper

  # Servlet registration
  register HostServlet
  register VulnServlet
  register EventServlet
  register WebServlet
  register OnlineTestServlet
  register NoteServlet
  register WorkspaceServlet
  register ServiceServlet
  register SessionServlet
  register ExploitServlet
  register LootServlet
  register SessionEventServlet
  register CredentialServlet
  register NmapServlet
end