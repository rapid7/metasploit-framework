require 'swagger/blocks'

module SessionEventApiDoc
  include Swagger::Blocks

# Swagger documentation for session events model
  swagger_schema :SessionEvent do
    key :required, [:id, :etype]
    property :id, type: :integer, format: :int32
    property :created_at, type: :string, format: :date_time
    property :session_id, type: :integer, format: :int32
    property :etype, type: :string
    property :command, type: :string
    property :output, type: :string
    property :remote_path, type: :string
    property :local_path, type: :string
  end

  swagger_path '/api/v1/session-events' do
    # Swagger documentation for /api/v1/session-events GET
    operation :get do
      key :description, 'Return session events that are stored in the database.'
      key :tags, [ 'session_event' ]

      response 200 do
        key :description, 'Returns session events data.'
        schema do
          key :type, :array
          items do
            key :'$ref', :SessionEvent
          end
        end
      end
    end

    # Swagger documentation for /api/v1/session events POST
    operation :post do
      key :description, 'Create a session events entry.'
      key :tags, [ 'session_event' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the session.'
        key :required, true
        schema do
          property :etype, type: :string, required: true
          property :local_path, type: :string
          property :command, type: :string
          property :session, '$ref' => :Session, required: true
        end
      end

      response 200 do
        key :description, 'Successful operation.'
        schema do
          key :type, :object
          key :'$ref', :SessionEvent
        end
      end
    end
  end
end
