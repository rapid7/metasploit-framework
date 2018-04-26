require 'swagger/blocks'

module LootApiDoc
  include Swagger::Blocks

# Swagger documentation for loot model
  swagger_schema :Loot do
    key :required, [:id, :name]
    property :id, type: :integer, format: :int32
    property :created_at, type: :string, format: :date_time
    property :updated_at, type: :string, format: :date_time
    property :workspace_id, type: :integer, format: :int32
    property :host_id, type: :integer, format: :int32
    property :service_id, type: :integer, format: :int32
    property :ltype, type: :string
    property :path, type: :string
    property :data, type: :string
    property :content_type, type: :string
    property :name, type: :string
    property :info, type: :string
    property :module_run_id, type: :integer, format: :int32
  end

  # Swagger documentation for /api/v1/loot GET
  swagger_path '/api/v1/loot' do
    operation :get do
      key :description, 'Return loot that are stored in the database.'

      parameter :workspace

      response 200 do
        key :description, 'Returns loot data'
        schema do
          key :type, :array
          items do
            key :'$ref', :Loot
          end
        end
      end
    end

    # Swagger documentation for /api/v1/loot POST
    operation :post do
      key :description, 'Create a loot entry.'

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the loot'
        key :required, true
        schema do
          key :'$ref', :Loot
        end
      end

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :object
          key :'$ref', :Loot
        end
      end
    end

    # Swagger documentation for /api/v1/loot/ DELETE
    operation :delete do
      key :description, 'Delete the specified loot.'

      parameter :delete_opts

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :array
          items do
            key :'$ref', :Loot
          end
        end
      end
    end
  end

  # Swagger documentation for api/v1/loot/:id GET
  swagger_path '/api/v1/loot/:id' do
    operation :get do
      key :description, 'Return loot that are stored in the database.'

      parameter :workspace

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of loot to retrieve'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns loot data'
        schema do
          key :type, :array
          items do
            key :'$ref', :Loot
          end
        end
      end
    end

    # Swagger documentation for /api/v1/loot/:id PUT
    operation :put do
      key :description, 'Update the attributes an existing loot.'

      parameter :update_id

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The updated attributes to overwrite to the loot'
        key :required, true
        schema do
          key :'$ref', :Loot
        end
      end

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :object
          key :'$ref', :Loot
        end
      end
    end
  end
end