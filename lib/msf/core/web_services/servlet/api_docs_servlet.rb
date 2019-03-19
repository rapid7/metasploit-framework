require 'swagger/blocks'
load 'documentation/api/v1/root_api_doc.rb'
load 'documentation/api/v1/async_callback_api_doc.rb'
load 'documentation/api/v1/auth_api_doc.rb'
load 'documentation/api/v1/credential_api_doc.rb'
load 'documentation/api/v1/db_export_api_doc.rb'
load 'documentation/api/v1/event_api_doc.rb'
load 'documentation/api/v1/exploit_api_doc.rb'
load 'documentation/api/v1/host_api_doc.rb'
load 'documentation/api/v1/login_api_doc.rb'
load 'documentation/api/v1/loot_api_doc.rb'
load 'documentation/api/v1/module_search_api_doc.rb'
load 'documentation/api/v1/msf_api_doc.rb'
load 'documentation/api/v1/nmap_api_doc.rb'
load 'documentation/api/v1/note_api_doc.rb'
load 'documentation/api/v1/payload_api_doc.rb'
load 'documentation/api/v1/service_api_doc.rb'
load 'documentation/api/v1/session_api_doc.rb'
load 'documentation/api/v1/session_event_api_doc.rb'
load 'documentation/api/v1/user_api_doc.rb'
load 'documentation/api/v1/vuln_api_doc.rb'
load 'documentation/api/v1/vuln_attempt_api_doc.rb'
load 'documentation/api/v1/workspace_api_doc.rb'


module ApiDocsServlet
  include Swagger::Blocks

  def self.json_path
    '/api/v1/api-docs.json'
  end

  def self.html_path
    '/api/v1/api-docs'
  end

  def self.registered(app)
    app.get ApiDocsServlet.json_path, &get_api_docs
    app.get ApiDocsServlet.html_path do
      erb :api_docs
    end
  end

  private

  def self.get_api_docs
    lambda {
      swaggered_classes = [
          RootApiDoc,
          AsyncCallbackApiDoc,
          AuthApiDoc,
          CredentialApiDoc,
          DbExportApiDoc,
          EventApiDoc,
          ExploitApiDoc,
          HostApiDoc,
          LoginApiDoc,
          LootApiDoc,
          ModuleSearchApiDoc,
          MsfApiDoc,
          NmapApiDoc,
          NoteApiDoc,
          PayloadApiDoc,
          ServiceApiDoc,
          SessionApiDoc,
          SessionEventApiDoc,
          UserApiDoc,
          VulnApiDoc,
          VulnAttemptApiDoc,
          WorkspaceApiDoc
      ].freeze
      json = Swagger::Blocks.build_root_json(swaggered_classes)
      set_json_response(json, [])
    }
  end
end
