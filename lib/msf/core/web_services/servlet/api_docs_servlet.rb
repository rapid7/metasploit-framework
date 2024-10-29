require 'swagger/blocks'

module Msf::WebServices::ApiDocsServlet
  include Swagger::Blocks

  def self.json_path
    '/api/v1/api-docs.json'
  end

  def self.html_path
    '/api/v1/api-docs'
  end

  def self.registered(app)
    app.get Msf::WebServices::ApiDocsServlet.json_path, &get_api_docs
    app.get Msf::WebServices::ApiDocsServlet.html_path do
      erb :api_docs
    end
  end

  private

  def self.get_api_docs
    lambda {
      swaggered_classes = [
          Msf::WebServices::Documentation::Api::V1::RootApiDoc,
          Msf::WebServices::Documentation::Api::V1::AuthApiDoc,
          Msf::WebServices::Documentation::Api::V1::CredentialApiDoc,
          Msf::WebServices::Documentation::Api::V1::DbExportApiDoc,
          Msf::WebServices::Documentation::Api::V1::EventApiDoc,
          Msf::WebServices::Documentation::Api::V1::ExploitApiDoc,
          Msf::WebServices::Documentation::Api::V1::HostApiDoc,
          Msf::WebServices::Documentation::Api::V1::LoginApiDoc,
          Msf::WebServices::Documentation::Api::V1::LootApiDoc,
          Msf::WebServices::Documentation::Api::V1::ModuleSearchApiDoc,
          Msf::WebServices::Documentation::Api::V1::MsfApiDoc,
          Msf::WebServices::Documentation::Api::V1::NmapApiDoc,
          Msf::WebServices::Documentation::Api::V1::NoteApiDoc,
          Msf::WebServices::Documentation::Api::V1::PayloadApiDoc,
          Msf::WebServices::Documentation::Api::V1::ServiceApiDoc,
          Msf::WebServices::Documentation::Api::V1::SessionApiDoc,
          Msf::WebServices::Documentation::Api::V1::SessionEventApiDoc,
          Msf::WebServices::Documentation::Api::V1::UserApiDoc,
          Msf::WebServices::Documentation::Api::V1::VulnApiDoc,
          Msf::WebServices::Documentation::Api::V1::VulnAttemptApiDoc,
          Msf::WebServices::Documentation::Api::V1::WorkspaceApiDoc
      ].freeze
      json = Swagger::Blocks.build_root_json(swaggered_classes)
      set_json_response(json, [])
    }
  end
end
