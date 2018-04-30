require 'swagger/blocks'

module ServiceApiDoc
  include Swagger::Blocks

# Swagger documentation for Service model
  swagger_schema :Service do
    key :required, [:id, :port, :proto]
    property :id, type: :integer, format: :int32
    property :host_id, type: :integer, format: :int32
    property :created_at, type: :string, format: :date_time
    property :port, type: :integer, format: :int32
    property :proto, type: :string, enum: ['tcp','udp']
    property :state, type: :string
    property :name, type: :string
    property :updated_at, type: :string, format: :date_time
    property :info, type: :string
  end

  # Swagger documentation for /api/v1/services GET
  swagger_path '/api/v1/services' do
    operation :get do
      key :description, 'Return services that are stored in the database.'
      key :tags, [ 'service' ]

      parameter :workspace

      response 200 do
        key :description, 'Returns Service data'
        schema do
          key :type, :array
          items do
            key :'$ref', :Service
          end
        end
      end
    end

    # Swagger documentation for /api/v1/services POST
    operation :post do
      key :description, 'Create a Service.'
      key :tags, [ 'service' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the Service'
        key :required, true
        schema do
          key :'$ref', :Service
        end
      end

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :object
          key :'$ref', :Service
        end
      end
    end

    # Swagger documentation for /api/v1/services/ DELETE
    operation :delete do
      key :description, 'Delete the specified services.'
      key :tags, [ 'service' ]

      parameter :delete_opts

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :array
          items do
            key :'$ref', :Service
          end
        end
      end
    end
  end

  # Swagger documentation for api/v1/services/:id GET
  swagger_path '/api/v1/services/:id' do
    operation :get do
      key :description, 'Return services that are stored in the database.'
      key :tags, [ 'service' ]

      parameter :workspace

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of Service to retrieve'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns Service data'
        schema do
          key :type, :array
          items do
            key :'$ref', :Service
          end
        end
      end
    end

    # Swagger documentation for /api/v1/services/:id PUT
    operation :put do
      key :description, 'Update the attributes an existing Service.'
      key :tags, [ 'service' ]

      parameter :update_id

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The updated attributes to overwrite to the Service'
        key :required, true
        schema do
          key :'$ref', :Service
        end
      end

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :object
          key :'$ref', :Service
        end
      end
    end
  end
end