require 'swagger/blocks'
load 'documentation/api/v1/root_api_doc.rb'
load 'documentation/api/v1/host_api_doc.rb'


module ApiDocsServlet
  include Swagger::Blocks

  def self.api_path
    '/api/v1/api-docs'
  end

  def self.registered(app)
    app.get ApiDocsServlet.api_path, &get_api_docs
  end

  private

  def self.get_api_docs
    lambda {
      swaggered_classes = [
          RootApiDoc,
          HostApiDoc
      ].freeze
      json = Swagger::Blocks.build_root_json(swaggered_classes)
      set_json_response(json, [])
    }
  end
end
