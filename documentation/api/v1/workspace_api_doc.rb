require 'swagger/blocks'

module WorkspaceApiDoc
  include Swagger::Blocks

# Swagger documentation for workspaces model
  swagger_schema :Workspace do
    key :required, [:id, :name]
    property :id, type: :integer, format: :int32
    property :created_at, type: :string, format: :date_time
    property :updated_at, type: :string, format: :date_time
    property :name, type: :string
    property :boundary, type: :string
    property :description, type: :string
    property :owner_id, type: :integer, format: :int32
    property :limit_to_network, type: :boolean
    property :import_fingerprint, type: :boolean
  end

  swagger_path '/api/v1/workspaces' do
    # Swagger documentation for /api/v1/workspaces GET
    operation :get do
      key :description, 'Return workspaces that are stored in the database.'
      key :tags, [ 'workspace' ]

      response 200 do
        key :description, 'Returns workspaces data'
        schema do
          key :type, :array
          items do
            key :'$ref', :Workspace
          end
        end
      end
    end

    # Swagger documentation for /api/v1/workspaces POST
    operation :post do
      key :description, 'Create a workspaces entry.'
      key :tags, [ 'workspace' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the workspaces'
        key :required, true
        schema do
          key :'$ref', :Workspace
        end
      end

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :object
          key :'$ref', :Workspace
        end
      end
    end

    # Swagger documentation for /api/v1/workspaces/ DELETE
    operation :delete do
      key :description, 'Delete the specified workspaces.'
      key :tags, [ 'workspace' ]

      parameter :delete_opts

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :array
          items do
            key :'$ref', :Workspace
          end
        end
      end
    end
  end

  swagger_path '/api/v1/workspaces/:id' do
    # Swagger documentation for api/v1/workspaces/:id GET
    operation :get do
      key :description, 'Return workspaces that are stored in the database.'
      key :tags, [ 'workspace' ]

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of workspaces to retrieve'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns workspaces data'
        schema do
          key :type, :array
          items do
            key :'$ref', :Workspace
          end
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
        key :description, 'The updated attributes to overwrite to the workspaces'
        key :required, true
        schema do
          key :'$ref', :Workspace
        end
      end

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :object
          key :'$ref', :Workspace
        end
      end
    end
  end
end