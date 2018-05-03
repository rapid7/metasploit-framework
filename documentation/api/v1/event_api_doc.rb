require 'swagger/blocks'

module EventApiDoc
  include Swagger::Blocks

# Swagger documentation for Event model
  swagger_schema :Event do
    key :required, [:id, :name]
    property :id, type: :integer, format: :int32
    property :created_at, type: :string, format: :date_time
    property :updated_at, type: :string, format: :date_time
    property :workspace_id, type: :integer, format: :int32
    property :name, type: :string
    property :critical, type: :string
    property :seen, type: :string
    property :username, type: :string
    property :info do
      key :type, :object
      property :revision, type: :string
    end
  end

  swagger_path '/api/v1/events' do
    # Swagger documentation for /api/v1/events POST
    operation :post do
      key :description, 'Create a host.'
      key :tags, [ 'event' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the host'
        key :required, true
        schema do
          key :'$ref', :Event
        end
      end

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :object
          key :'$ref', :Event
        end
      end
    end
  end
end