require 'swagger/blocks'

module Msf::WebServices::Documentation::Api::V1::EventApiDoc
  include Swagger::Blocks

  NAME_DESC = 'The name of the event.'
  NAME_EXAMPLE = 'module_run'
  HOST_DESC = 'The address of the host related to this event.'
  CRITICAL_DESC = 'true if the event is considered critical.'
  SEEN_DESC = 'true if a user has acknowledged the event.'
  USERNAME_DESC = 'Name of the user that triggered the event.'
  INFO_DESC = 'Information about the event specific to the event name.'
  INFO_EXAMPLE = {command: 'irb'}

# Swagger documentation for Event model
  swagger_schema :Event do
    key :required, [:name]
    property :id, type: :integer, format: :int32, description: Msf::WebServices::Documentation::Api::V1::RootApiDoc::ID_DESC
    property :workspace_id, type: :integer, format: :int32, description: Msf::WebServices::Documentation::Api::V1::RootApiDoc::WORKSPACE_ID_DESC
    property :name, type: :string, description: NAME_DESC, example: NAME_EXAMPLE
    property :critical, type: :boolean, description: CRITICAL_DESC
    property :seen, type: :string, description: SEEN_DESC
    property :username, type: :string, description: USERNAME_DESC
    property :info, type: :string, description: INFO_DESC, example: INFO_EXAMPLE
    property :created_at, type: :string, format: :date_time, description: Msf::WebServices::Documentation::Api::V1::RootApiDoc::CREATED_AT_DESC
    property :updated_at, type: :string, format: :date_time, description: Msf::WebServices::Documentation::Api::V1::RootApiDoc::CREATED_AT_DESC
  end

  swagger_path '/api/v1/events' do
    # Swagger documentation for /api/v1/events GET
    operation :get do
      key :description, 'Return events that are stored in the database.'
      key :tags, [ 'event' ]

      parameter :workspace

      parameter do
        key :name, :limit
        key :in, :query
        key :description, Msf::WebServices::Documentation::Api::V1::RootApiDoc::LIMIT_DESC
        key :example, Msf::WebServices::Documentation::Api::V1::RootApiDoc::LIMIT_DEFAULT
        key :type, :integer
        key :format, :int32
        key :required, false
      end

      parameter do
        key :name, :offset
        key :in, :query
        key :description, Msf::WebServices::Documentation::Api::V1::RootApiDoc::OFFSET_DESC
        key :example, Msf::WebServices::Documentation::Api::V1::RootApiDoc::OFFSET_DEFAULT
        key :type, :integer
        key :format, :int32
        key :required, false
      end

      parameter do
        key :name, :order
        key :in, :query
        key :description, Msf::WebServices::Documentation::Api::V1::RootApiDoc::ORDER_DESC
        key :type, :string
        key :required, false
        key :enum, Msf::WebServices::Documentation::Api::V1::RootApiDoc::ORDER_ENUM
      end

      response 200 do
        key :description, 'Returns event data.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :Event
            end
          end
        end
      end

      response 401 do
        key :description, Msf::WebServices::Documentation::Api::V1::RootApiDoc::DEFAULT_RESPONSE_401
        schema do
          key :'$ref', :AuthErrorModel
        end
      end

      response 500 do
        key :description, Msf::WebServices::Documentation::Api::V1::RootApiDoc::DEFAULT_RESPONSE_500
        schema do
          key :'$ref', :ErrorModel
        end
      end
    end

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
          property :workspace, type: :string, required: true, description: Msf::WebServices::Documentation::Api::V1::RootApiDoc::WORKSPACE_POST_DESC, example: Msf::WebServices::Documentation::Api::V1::RootApiDoc::WORKSPACE_POST_EXAMPLE
          property :name, type: :string, description: NAME_DESC, example: NAME_EXAMPLE
          property :host, type: :string, format: :ipv4, description: HOST_DESC, example: Msf::WebServices::Documentation::Api::V1::RootApiDoc::HOST_EXAMPLE
          property :critical, type: :boolean, description: CRITICAL_DESC
          property :username, type: :string, description: USERNAME_DESC
          property :info, type: :string, description: INFO_DESC, example: INFO_EXAMPLE
        end
      end

      response 200 do
        key :description, Msf::WebServices::Documentation::Api::V1::RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :'$ref', :Event
          end
        end
      end

      response 401 do
        key :description, Msf::WebServices::Documentation::Api::V1::RootApiDoc::DEFAULT_RESPONSE_401
        schema do
          key :'$ref', :AuthErrorModel
        end
      end

      response 500 do
        key :description, Msf::WebServices::Documentation::Api::V1::RootApiDoc::DEFAULT_RESPONSE_500
        schema do
          key :'$ref', :ErrorModel
        end
      end
    end
  end

  swagger_path '/api/v1/events/{id}' do
    # Swagger documentation for /api/v1/events/:id GET
    operation :get do
      key :description, 'Return a specific event that is stored in the database.'
      key :tags, [ 'event' ]

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of event to retrieve.'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns event data.'
        schema do
          property :data do
            key :'$ref', :Event
          end
        end
      end

      response 401 do
        key :description, Msf::WebServices::Documentation::Api::V1::RootApiDoc::DEFAULT_RESPONSE_401
        schema do
          key :'$ref', :AuthErrorModel
        end
      end

      response 500 do
        key :description, Msf::WebServices::Documentation::Api::V1::RootApiDoc::DEFAULT_RESPONSE_500
        schema do
          key :'$ref', :ErrorModel
        end
      end
    end
  end
end
