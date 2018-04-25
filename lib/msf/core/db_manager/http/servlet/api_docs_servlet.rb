require 'swagger/blocks'

module ApiDocsServlet
  include Swagger::Blocks

  def self.api_path
    '/api/v1/api-docs'
  end

  def self.registered(app)
    app.get ApiDocsServlet.api_path, &get_api_docs
  end

  swagger_root do
    key :swagger, '2.0'
    info do
      key :version, '1.0.0'
      key :title, 'Metasploit API'
      key :description, 'An API for interacting with Metasploit\'s data models'
      license do
        key :name, 'BSD-3-clause'
      end
    end

    key :host, 'localhost'
    key :basePath, '/api/v1'
    key :consumes, ['application/json']
    key :produces, ['application/json']
  end

  private

  def self.get_api_docs
    lambda {
      swaggerd_classes = [
          HostServlet,
          ApiDocsServlet
      ].freeze
      json = Swagger::Blocks.build_root_json(swaggerd_classes)
      set_json_response(json, [])
    }
  end
end
