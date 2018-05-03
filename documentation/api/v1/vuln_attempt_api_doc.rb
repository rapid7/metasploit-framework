require 'swagger/blocks'

module VulnAttemptApiDoc
  include Swagger::Blocks

# Swagger documentation for vuln_attempts model
  swagger_schema :VulnAttempt do
    key :required, [:id]
    property :id, type: :integer, format: :int32
    property :attempted_at, type: :string, format: :date_time
    property :vuln_id, type: :integer, format: :int32
    property :exploited, type: :bool
    property :fail_reason, type: :string
    property :username, type: :string
    property :module, type: :string
    property :session_id, type: :integer, format: :int32
    property :loot_id, type: :integer, format: :int32
    property :fail_detail, type: :string
  end

  swagger_path '/api/v1/vuln-attempts' do
    # Swagger documentation for /api/v1/vuln-attempts GET
    operation :get do
      key :description, 'Return vuln attempts that are stored in the database.'
      key :tags, [ 'vuln_attempt' ]

      response 200 do
        key :description, 'Returns vuln attempt data'
        schema do
          key :type, :array
          items do
            key :'$ref', :VulnAttempt
          end
        end
      end
    end

    # Swagger documentation for /api/v1/vuln-attempts POST
    operation :post do
      key :description, 'Create a vuln attempt entry.'
      key :tags, [ 'vuln_attempt' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the vuln_attempt'
        key :required, true
        schema do
          key :'$ref', :VulnAttempt
        end
      end

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :object
          key :'$ref', :VulnAttempt
        end
      end
    end
  end
end