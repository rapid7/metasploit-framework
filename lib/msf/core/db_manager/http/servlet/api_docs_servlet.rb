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

    #################################
    #
    # Global parameters
    #
    #################################
    parameter :workspace do
      key :name, :workspace
      key :in, :query
      key :description, 'The workspace from which the data should be gathered from.'
      key :required, true
      key :type, :string
    end

    parameter :update_id do
      key :name, :id
      key :in, :path
      key :description, 'ID of the object to update'
      key :required, true
      key :type, :integer
      key :format, :int32
    end

    parameter :delete_opts do
      key :in, :body
      key :name, :delete_opts
      key :description, 'The IDs of the objects you want to delete.'
      key :required, true
      schema do
        key :required, [:ids]
        property :ids do
          key :type, :array
          items do
            key :type, :integer
          end
        end
      end
    end

    #################################
    #
    # Host related parameters
    #
    #################################
    parameter :non_dead do
      key :name, :non_dead
      key :in, :query
      key :description, 'true to return only hosts which are up, false for all hosts.'
      key :required, false
      key :type, :boolean
    end

    parameter :address do
      key :name, :address
      key :in, :query
      key :description, 'Return hosts matching the given IP address.'
      key :required, false
      key :type, :string
    end
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
