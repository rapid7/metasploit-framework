require 'swagger/blocks'

module HostApiDoc
  include Swagger::Blocks

# Swagger documentation for Host model
  swagger_schema :Host do
    key :required, [:id, :name]
    property :id, type: :integer, format: :int32
    property :created_at, type: :string, format: :date_time
    property :address, type: :string
    property :mac, type: :string
    property :comm, type: :string
    property :name, type: :string
    property :state, type: :string
    property :os_name, type: :string
    property :os_flavor, type: :string
    property :os_sp, type: :string
    property :os_lang, type: :string
    property :arch, type: :string
    property :workspace_id, type: :integer, format: :int32
    property :updated_at, type: :string, format: :date_time
    property :purpose, type: :string
    property :info, type: :string
    property :comments, type: :string
    property :scope, type: :string
    property :virtual_host, type: :string
    property :note_count, type: :integer, format: :int32
    property :vuln_count, type: :integer, format: :int32
    property :service_count, type: :integer, format: :int32
    property :host_detail_count, type: :integer, format: :int32
    property :exploit_attempt_count, type: :integer, format: :int32
    property :cred_count, type: :integer, format: :int32
    property :detected_arch, type: :string
    property :os_family, type: :string
  end

  # Swagger documentation for /api/v1/hosts GET
  swagger_path '/api/v1/hosts' do
    operation :get do
      key :description, 'Return hosts that are stored in the database.'
      key :tags, [ 'host' ]

      parameter :workspace
      parameter :non_dead
      parameter :address

      response 200 do
        key :description, 'Returns host data'
        schema do
          key :type, :array
          items do
            key :'$ref', :Host
          end
        end
      end
    end

    # Swagger documentation for /api/v1/hosts POST
    operation :post do
      key :description, 'Create a host.'
      key :tags, [ 'host' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the host'
        key :required, true
        schema do
          key :'$ref', :Host
        end
      end

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :object
          key :'$ref', :Host
        end
      end
    end

    # Swagger documentation for /api/v1/hosts/ DELETE
    operation :delete do
      key :description, 'Delete the specified hosts.'
      key :tags, [ 'host' ]

      parameter :delete_opts

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :array
          items do
            key :'$ref', :Host
          end
        end
      end
    end
  end

  # Swagger documentation for api/v1/hosts/:id GET
  swagger_path '/api/v1/hosts/:id' do
    operation :get do
      key :description, 'Return hosts that are stored in the database.'
      key :tags, [ 'host' ]

      parameter :workspace
      parameter :non_dead
      parameter :address

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of host to retrieve'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns host data'
        schema do
          key :type, :array
          items do
            key :'$ref', :Host
          end
        end
      end
    end

    # Swagger documentation for /api/v1/hosts/:id PUT
    operation :put do
      key :description, 'Update the attributes an existing host.'
      key :tags, [ 'host' ]

      parameter :update_id

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The updated attributes to overwrite to the host'
        key :required, true
        schema do
          key :'$ref', :Host
        end
      end

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :object
          key :'$ref', :Host
        end
      end
    end
  end
end