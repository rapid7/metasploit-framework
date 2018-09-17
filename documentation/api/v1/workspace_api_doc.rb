require 'swagger/blocks'

module WorkspaceApiDoc
  include Swagger::Blocks

  NAME_DESC = 'The name of the workspace. This is the unique identifier for determining which workspace is being accessed.'
  BOUNDARY_DESC = 'Comma separated list of IP ranges (in various formats) and IP addresses that users of this workspace are allowed to interact with if limit_to_network is true.'
  BOUNDARY_EXAMPLE = '10.10.1.1-50,10.10.1.100,10.10.2.0/24'
  DESCRIPTION_DESC = 'Long description that explains the purpose of this workspace.'
  OWNER_ID_DESC = 'ID of the user who owns this workspace.'
  LIMIT_TO_NETWORK_DESC = 'true to restrict the hosts and services in this workspace to the IP addresses listed in \'boundary\'.'
  IMPORT_FINGERPRINT_DESC = 'Identifier that indicates if and where this workspace was imported from.'

# Swagger documentation for workspaces model
  swagger_schema :Workspace do
    key :required, [:name]
    property :id, type: :integer, format: :int32, description: RootApiDoc::ID_DESC
    property :name, type: :string, description: NAME_DESC
    property :boundary, type: :string, description: BOUNDARY_DESC, example: BOUNDARY_EXAMPLE
    property :description, type: :string, description: DESCRIPTION_DESC
    property :owner_id, type: :integer, format: :int32, description: OWNER_ID_DESC
    property :limit_to_network, type: :boolean, description: LIMIT_TO_NETWORK_DESC
    property :import_fingerprint, type: :boolean, description: IMPORT_FINGERPRINT_DESC
    property :created_at, type: :string, format: :date_time, description: RootApiDoc::CREATED_AT_DESC
    property :updated_at, type: :string, format: :date_time, description: RootApiDoc::UPDATED_AT_DESC
  end

  swagger_path '/api/v1/workspaces' do
    # Swagger documentation for /api/v1/workspaces GET
    operation :get do
      key :description, 'Return workspaces that are stored in the database.'
      key :tags, [ 'workspace' ]

      response 200 do
        key :description, 'Returns workspace data.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :Workspace
            end
          end
        end
      end

      response 401 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_401
        schema do
          key :'$ref', :AuthErrorModel
        end
      end

      response 500 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_500
        schema do
          key :'$ref', :ErrorModel
        end
      end
    end

    # Swagger documentation for /api/v1/workspaces POST
    operation :post do
      key :description, 'Create a workspace entry.'
      key :tags, [ 'workspace' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the workspace.'
        key :required, true
        schema do
          property :name, type: :string, description: NAME_DESC
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :'$ref', :Workspace
          end
        end
      end

      response 401 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_401
        schema do
          key :'$ref', :AuthErrorModel
        end
      end

      response 500 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_500
        schema do
          key :'$ref', :ErrorModel
        end
      end
    end

    # Swagger documentation for /api/v1/workspaces/ DELETE
    operation :delete do
      key :description, 'Delete the specified workspaces.'
      key :tags, [ 'workspace' ]

      parameter :delete_opts

      response 200 do
        key :description, 'Returns an array containing the successfully deleted workspaces.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :Workspace
            end
          end
        end
      end

      response 401 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_401
        schema do
          key :'$ref', :AuthErrorModel
        end
      end

      response 500 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_500
        schema do
          key :'$ref', :ErrorModel
        end
      end
    end
  end

  swagger_path '/api/v1/workspaces/{id}' do
    # Swagger documentation for api/v1/workspaces/:id GET
    operation :get do
      key :description, 'Return specific workspace that is stored in the database.'
      key :tags, [ 'workspace' ]

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of workspace to retrieve.'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns workspace data.'
        schema do
          property :data do
            key :'$ref', :Workspace
          end
        end
      end

      response 401 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_401
        schema do
          key :'$ref', :AuthErrorModel
        end
      end

      response 500 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_500
        schema do
          key :'$ref', :ErrorModel
        end
      end
    end

    # Swagger documentation for /api/v1/workspaces/:id PUT
    operation :put do
      key :description, 'Update the attributes an existing workspaces.'
      key :tags, [ 'workspace' ]

      parameter :update_id

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The updated attributes to overwrite to the workspace.'
        key :required, true
        schema do
          key :'$ref', :Workspace
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :'$ref', :Workspace
          end
        end
      end

      response 401 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_401
        schema do
          key :'$ref', :AuthErrorModel
        end
      end

      response 500 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_500
        schema do
          key :'$ref', :ErrorModel
        end
      end
    end
  end
end
