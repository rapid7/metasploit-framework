require 'swagger/blocks'

module NoteApiDoc
  include Swagger::Blocks

# Swagger documentation for notes model
  swagger_schema :Note do
    key :required, [:id, :ntype]
    property :id, type: :integer, format: :int32
    property :created_at, type: :string, format: :date_time
    property :updated_at, type: :string, format: :date_time
    property :ntype, type: :string
    property :workspace_id, type: :integer, format: :int32
    property :host_id, type: :integer, format: :int32
    property :service_id, type: :integer, format: :int32
    property :critical, type: :string
    property :seen, type: :string
    property :data, type: :string
    property :vuln_id, type: :integer, format: :int32
  end

  # Swagger documentation for /api/v1/notes GET
  swagger_path '/api/v1/notes' do
    operation :get do
      key :description, 'Return notes that are stored in the database.'

      parameter :workspace

      response 200 do
        key :description, 'Returns notes data'
        schema do
          key :type, :array
          items do
            key :'$ref', :Note
          end
        end
      end
    end

    # Swagger documentation for /api/v1/notes POST
    operation :post do
      key :description, 'Create a notes entry.'

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the notes'
        key :required, true
        schema do
          key :'$ref', :Note
        end
      end

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :object
          key :'$ref', :Note
        end
      end
    end

    # Swagger documentation for /api/v1/notes/ DELETE
    operation :delete do
      key :description, 'Delete the specified notes.'

      parameter :delete_opts

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :array
          items do
            key :'$ref', :Note
          end
        end
      end
    end
  end

  # Swagger documentation for api/v1/notes/:id GET
  swagger_path '/api/v1/notes/:id' do
    operation :get do
      key :description, 'Return notes that are stored in the database.'

      parameter :workspace

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of notes to retrieve'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns notes data'
        schema do
          key :type, :array
          items do
            key :'$ref', :Note
          end
        end
      end
    end

    # Swagger documentation for /api/v1/notes/:id PUT
    operation :put do
      key :description, 'Update the attributes an existing notes.'

      parameter :update_id

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The updated attributes to overwrite to the notes'
        key :required, true
        schema do
          key :'$ref', :Note
        end
      end

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :object
          key :'$ref', :Note
        end
      end
    end
  end
end