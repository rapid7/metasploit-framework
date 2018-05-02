require 'swagger/blocks'
load 'documentation/api/v1/root_api_doc.rb'
load 'documentation/api/v1/host_api_doc.rb'
load 'documentation/api/v1/loot_api_doc.rb'
load 'documentation/api/v1/note_api_doc.rb'
load 'documentation/api/v1/service_api_doc.rb'
load 'documentation/api/v1/session_api_doc.rb'
load 'documentation/api/v1/vuln_api_doc.rb'
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
          HostApiDoc,
          LootApiDoc,
          NoteApiDoc,
          ServiceApiDoc,
          SessionApiDoc,
          VulnApiDoc,
          WorkspaceApiDoc
      ].freeze
      json = Swagger::Blocks.build_root_json(swaggered_classes)
      set_json_response(json, [])
    }
  end
end
