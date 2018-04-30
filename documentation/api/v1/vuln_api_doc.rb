require 'swagger/blocks'

module VulnApiDoc
  include Swagger::Blocks

# Swagger documentation for vulns model
  swagger_schema :Vuln do
    key :required, [:id, :name]
    property :id, type: :integer, format: :int32
    property :created_at, type: :string, format: :date_time
    property :updated_at, type: :string, format: :date_time
    property :name, type: :string
    property :info, type: :string
    property :exploited_at, type: :string, format: :date_time
    property :vuln_detail_count, type: :integer, format: :int32
    property :vuln_attempt_count, type: :integer, format: :int32
    property :origin_id, type: :integer, format: :int32
    property :origin_type, type: :integer, format: :int32
  end

  # Swagger documentation for /api/v1/vulns GET
  swagger_path '/api/v1/vulns' do
    operation :get do
      key :description, 'Return vulns that are stored in the database.'

      parameter :workspace

      response 200 do
        key :description, 'Returns vulns data'
        schema do
          key :type, :array
          items do
            key :'$ref', :Vuln
          end
        end
      end
    end

    # Swagger documentation for /api/v1/vulns POST
    operation :post do
      key :description, 'Create a vulns entry.'

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the vulns'
        key :required, true
        schema do
          key :'$ref', :Vuln
        end
      end

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :object
          key :'$ref', :Vuln
        end
      end
    end

    # Swagger documentation for /api/v1/vulns/ DELETE
    operation :delete do
      key :description, 'Delete the specified vulns.'

      parameter :delete_opts

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :array
          items do
            key :'$ref', :Vuln
          end
        end
      end
    end
  end

  # Swagger documentation for api/v1/vulns/:id GET
  swagger_path '/api/v1/vulns/:id' do
    operation :get do
      key :description, 'Return vulns that are stored in the database.'

      parameter :workspace

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of vulns to retrieve'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns vulns data'
        schema do
          key :type, :array
          items do
            key :'$ref', :Vuln
          end
        end
      end
    end

    # Swagger documentation for /api/v1/vulns/:id PUT
    operation :put do
      key :description, 'Update the attributes an existing vulns.'

      parameter :update_id

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The updated attributes to overwrite to the vulns'
        key :required, true
        schema do
          key :'$ref', :Vuln
        end
      end

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :object
          key :'$ref', :Vuln
        end
      end
    end
  end
end