require 'swagger/blocks'

module EventApiDoc
  include Swagger::Blocks

  NAME_DESC = 'The name of the event.'
  NAME_EXAMPLE = 'module_run'
  HOST_DESC = 'The address of the host related to this event.'
  CRITICAL_DESC = 'true if the event is considered critical.'
  SEEN_DESC = 'true if a user has acknowledged the event.'
  USERNAME_DESC = 'Name of the user that triggered the event.'
  INFO_DESC = 'Information about the event specific to the event name.'
  INFO_EXAMPLE = '{:command=>"irb"}'

# Swagger documentation for Event model
  swagger_schema :Event do
    key :required, [:name]
    property :id, type: :integer, format: :int32, description: RootApiDoc::ID_DESC
    property :workspace_id, type: :integer, format: :int32, description: RootApiDoc::WORKSPACE_ID_DESC
    property :name, type: :string, description: NAME_DESC, example: NAME_EXAMPLE
    property :critical, type: :boolean, description: CRITICAL_DESC
    property :seen, type: :string, description: SEEN_DESC
    property :username, type: :string, description: USERNAME_DESC
    property :info, type: :string, description: INFO_DESC, example: INFO_EXAMPLE
    property :created_at, type: :string, format: :date_time, description: RootApiDoc::CREATED_AT_DESC
    property :updated_at, type: :string, format: :date_time, description: RootApiDoc::CREATED_AT_DESC
  end

  swagger_path '/api/v1/events' do
    # Swagger documentation for /api/v1/events POST
    operation :post do
      key :description, 'Create an event.'
      key :tags, [ 'event' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the event.'
        key :required, true
        schema do
          property :workspace, type: :string, required: true, description: RootApiDoc::WORKSPACE_POST_DESC, example: RootApiDoc::WORKSPACE_POST_EXAMPLE
          property :name, type: :string, description: NAME_DESC, example: NAME_EXAMPLE
          property :host, type: :string, format: :ipv4, description: HOST_DESC, example: RootApiDoc::HOST_EXAMPLE
          property :critical, type: :boolean, description: CRITICAL_DESC
          property :username, type: :string, description: USERNAME_DESC
          property :info, type: :string, description: INFO_DESC, example: INFO_EXAMPLE
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :'$ref', :Event
          end
        end
      end

      response 401 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_401
        schema do
          key :'$ref', :AuthErrorModel
        end
      end

      response 500 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_500
        schema do
          key :'$ref', :ErrorModel
        end
      end
    end
  end
end
