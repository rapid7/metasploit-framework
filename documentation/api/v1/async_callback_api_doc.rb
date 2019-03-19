require 'swagger/blocks'

module AsyncCallbackApiDoc
  include Swagger::Blocks

  UUID_DESC = 'The unique ID of the payload calling back'
  UUID_EXAMPLE = '6dde5ce0e94c9f43'
  TIMESTAMP_DESC = 'The Unix format timestamp when the asynchronous payload called back (in epoch)'
  TIMESTAMP_EXAMPLE = '1536777407'
  LISTENER_URI_DESC = 'The URL of the listener which received the callback'
  LISTENER_URI_EXAMPLE = ['tcp://192.168.1.7:4444', 'icmp://192.168.0.12', 'https://203.0.113.5:443/506eb417-782f-4f0b-9bc2-b30abe19d601']
  HOST_DESC = 'The IP address from which the callback was received'
  HOST_EXAMPLE = ['203.0.113.5']
  PORT_DESC = 'The port from which the callback was received'
  PORT_EXAMPLE = ['443']
  WORKSPACE_ID_DESC = 'The ID of the workspace this payload belongs to'
  WORKSPACE_ID_EXAMPLE = 'default'

# Swagger documentation for payloads model
  swagger_schema :AsyncCallback do
    key :required, [:ntype]
    property :workspace, type: :string, required: true, description: RootApiDoc::WORKSPACE_POST_EXAMPLE
    property :id, type: :integer, format: :int32, description: RootApiDoc::ID_DESC
    property :uuid, type: :string, required: true, description: UUID_DESC, example: UUID_EXAMPLE
    property :timestamp, type: :integer, required: true, description: TIMESTAMP_DESC, example: TIMESTAMP_EXAMPLE
    property :listener_uri, description: LISTENER_URI_DESC, example: LISTENER_URI_EXAMPLE, type: :array do items type: :string end
    property :target_host, type: :string, description: HOST_DESC, example: HOST_EXAMPLE
    property :target_port, type: :string, description: PORT_DESC, example: PORT_EXAMPLE
    property :created_at, type: :string, format: :date_time, description: RootApiDoc::CREATED_AT_DESC
    property :updated_at, type: :string, format: :date_time, description: RootApiDoc::UPDATED_AT_DESC
  end

  swagger_path '/api/v1/async-callbacks' do
    # Swagger documentation for /api/v1/async_callbacks GET
    operation :get do
      key :description, 'Return asynchronous payload callbacks that are stored in the database.'
      key :tags, [ 'async_callback' ]

      parameter :workspace

      response 200 do
        key :description, 'Returns asynchronous payload callback data.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :AsyncCallback
            end
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

    # Swagger documentation for /api/v1/async_callbacks POST
    operation :post do
      key :description, 'Create an asynchronous payload callback entry.'
      key :tags, [ 'async_callback' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the asynchronous payload callback.'
        key :required, true
        schema do
          property :uuid, type: :string, description: UUID_DESC, example: UUID_EXAMPLE
          property :timestamp, type: :string, description: TIMESTAMP_DESC, example: TIMESTAMP_EXAMPLE
          property :listener_uri, type: :string, description: LISTENER_URI_DESC, example: LISTENER_URI_EXAMPLE
          property :workspace_id, type: :string, description: WORKSPACE_ID_DESC, example: WORKSPACE_ID_EXAMPLE
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :'$ref', :AsyncCallback
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

  swagger_path '/api/v1/async-callbacks/{id}' do
    # Swagger documentation for api/v1/async-callbacks/:id GET
    operation :get do
      key :description, 'Return specific asynchronous payload callback that is stored in the database.'
      key :tags, [ 'async_callback' ]

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of asynchronous payload callback to retrieve.'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns asynchronous payload callback data.'
        schema do
          property :data do
            key :'$ref', :AsyncCallback
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
