require 'swagger/blocks'

module PayloadApiDoc
  include Swagger::Blocks

  NAME_DESC = 'A name for the payload.'
  UUID_DESC = 'A payload\'s unique identifier.'
  UUID_EXAMPLE = '6dde5ce0e94c9f43'
  TIMESTAMP_DESC = 'The Unix format timestamp when this payload was created.'
  TIMESTAMP_EXAMPLE = '1536777407'
  ARCH_DESC = 'The architecture this payload supports.'
  ARCH_EXAMPLE = 'x86'
  PLATFORM_DESC = 'The platform this payload supports.'
  PLATFORM_EXAMPLE = 'windows'
  URLS_DESC = 'The unique, encoded urls used to host this payload. Only applicable for http(s) payloads.'
  URLS_EXAMPLE = ['/bd5c4OlMn0OeQp9AxdvC_Q2EIcdSRvg7gzLdQwU__Mb1WtjGR8C4UbjohhRIgbmBfFFBsNJ-wZMyFZKK33aorc8qfD0xCsmxSEyHaiyjGn0ykbJOlYFF1j1HXShiKiiwbfh_wPf2uqSWk2tnaLAqwuvxPcRuDPF-kdkmDDC2']
  DESCRIPTION_DESC = 'A description of why this payload was created and what it is being used for.'
  WORKSPACE_ID_DESC = 'The ID of the workspace this payload belongs to.'
  WORKSPACE_ID_EXAMPLE = 1
  RAW_PAYLOAD_DESC = 'A URL pointing to where the binary payload can be downloaded from.'
  RAW_PAYLOAD_HASH_DESC = 'The unique hash value for the generated payload binary.'
  BUILD_OPTS_DESC = 'A hash containing various options used to build this payload.'

# Swagger documentation for payloads model
  swagger_schema :Payload do
    key :required, [:ntype]
    property :workspace, type: :string, required: true, description: RootApiDoc::WORKSPACE_POST_EXAMPLE
    property :id, type: :integer, format: :int32, description: RootApiDoc::ID_DESC
    property :name, type: :string, description: NAME_DESC
    property :uuid, type: :string, description: UUID_DESC, example: UUID_EXAMPLE
    property :timestamp, type: :integer, description: TIMESTAMP_DESC, example: TIMESTAMP_EXAMPLE
    property :arch, type: :string, description: ARCH_DESC, example: ARCH_EXAMPLE
    property :platform, type: :string, description: PLATFORM_DESC, example: PLATFORM_EXAMPLE
    property :urls, description: URLS_DESC, example: URLS_EXAMPLE, type: :array do items type: :string end
    property :description, type: :string, description: DESCRIPTION_DESC
    property :raw_payload, type: :string, description: RAW_PAYLOAD_DESC
    property :raw_payload_hash, type: :string, description: RAW_PAYLOAD_HASH_DESC
    property :build_opts, type: :string, description: BUILD_OPTS_DESC
    property :created_at, type: :string, format: :date_time, description: RootApiDoc::CREATED_AT_DESC
    property :updated_at, type: :string, format: :date_time, description: RootApiDoc::UPDATED_AT_DESC
  end

  swagger_path '/api/v1/payloads' do
    # Swagger documentation for /api/v1/payloads GET
    operation :get do
      key :description, 'Return payloads that are stored in the database.'
      key :tags, [ 'payload' ]

      parameter :workspace

      response 200 do
        key :description, 'Returns payload data.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :Payload
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

    # Swagger documentation for /api/v1/payloads POST
    operation :post do
      key :description, 'Create a payload entry.'
      key :tags, [ 'payload' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the payload.'
        key :required, true
        schema do
          property :name, type: :string, description: NAME_DESC
          property :uuid, type: :string, description: UUID_DESC, example: UUID_EXAMPLE
          property :timestamp, type: :string, description: TIMESTAMP_DESC, example: TIMESTAMP_EXAMPLE
          property :arch, type: :string, description: ARCH_DESC, example: ARCH_EXAMPLE
          property :platform, type: :string, description: PLATFORM_DESC, example: PLATFORM_EXAMPLE
          property :urls, type: :string, description: URLS_DESC, example: URLS_EXAMPLE
          property :description, type: :string, description: DESCRIPTION_DESC
          property :raw_payload, type: :string, description: RAW_PAYLOAD_DESC
          property :raw_payload_hash, type: :string, description: RAW_PAYLOAD_HASH_DESC
          property :build_opts, type: :string, description: BUILD_OPTS_DESC
          property :workspace_id, type: :string, description: WORKSPACE_ID_DESC, example: WORKSPACE_ID_EXAMPLE
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :'$ref', :Payload
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

    # Swagger documentation for /api/v1/payloads/ DELETE
    operation :delete do
      key :description, 'Delete the specified payloads.'
      key :tags, [ 'payload' ]

      parameter :delete_opts

      response 200 do
        key :description, 'Returns an array containing the successfully deleted payloads.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :Payload
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
  end

  swagger_path '/api/v1/payloads/{id}' do
    # Swagger documentation for api/v1/payloads/:id GET
    operation :get do
      key :description, 'Return specific payload that is stored in the database.'
      key :tags, [ 'payload' ]

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of payload to retrieve.'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns payload data.'
        schema do
          property :data do
            key :'$ref', :Payload
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

    # Swagger documentation for /api/v1/payloads/:id PUT
    operation :put do
      key :description, 'Update the attributes an existing payload.'
      key :tags, [ 'payload' ]

      parameter :update_id

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The updated attributes to overwrite to the payload.'
        key :required, true
        schema do
          key :'$ref', :Payload
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :'$ref', :Payload
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
