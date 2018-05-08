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
    property :critical, type: :boolean
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
        key :description, 'The attributes to assign to the event.'
        key :required, true
        schema do
          property :workspace, type: :string, required: true
          property :name, type: :string
          property :host, type: :string, format: :ipv4
          property :critical, type: :boolean
          property :username, type: :string
          property :info do
            key :type, :object
            property :revision, type: :string
          end
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