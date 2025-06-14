require 'swagger/blocks'

module Msf::WebServices::Documentation::Api::V1::LootApiDoc
  include Swagger::Blocks

  HOST_ID_DESC = 'The ID of the host record this loot is associated with.'
  HOST_DESC = 'The IP address of the host from where the loot was obtained.'
  SERVICE_ID_DESC = 'The ID of the service record this loot is associated with.'
  LTYPE_DESC = 'The type of loot.'
  LTYPE_EXAMPLE = "'file', 'image', 'config_file', etc."
  PATH_DESC = 'The on-disk path to the loot file.'
  PATH_EXAMPLE = '/path/to/file.txt'
  DATA_DESC = "Base64 encoded copy of the file's contents."
  DATA_EXAMPLE = 'dGhpcyBpcyB0aGUgZmlsZSdzIGNvbnRlbnRz'
  CONTENT_TYPE_DESC = 'The mime/content type of the file at {#path}.  Used to server the file correctly so browsers understand whether to render or download the file.'
  CONTENT_TYPE_EXAMPLE = 'text/plain'
  NAME_DESC = 'The name of the loot.'
  NAME_EXAMPLE = 'password_file.txt'
  INFO_DESC = 'Information about the loot.'
  MODULE_RUN_ID_DESC = 'The ID of the module run record this loot is associated with.'

  # Some of the attributes expect different data when doing a create.
  CREATE_PATH_DESC = 'The name to give the file on the server. All files are stored in a server configured path, so a full path is not needed. If there is a corresponding file on disk, the given value will be prepended with a unique string to prevent accidental overwrites of other files.'
  CREATE_PATH_EXAMPLE = 'password_file.txt'

# Swagger documentation for loot model
  swagger_schema :Loot do
    key :required, [:name, :ltype, :path]
    property :id, type: :integer, format: :int32, description: Msf::WebServices::Documentation::Api::V1::RootApiDoc::ID_DESC
    property :workspace_id, type: :integer, format: :int32, description: Msf::WebServices::Documentation::Api::V1::RootApiDoc::WORKSPACE_ID_DESC
    property :host_id, type: :integer, format: :int32, description: HOST_ID_DESC
    property :service_id, type: :integer, format: :int32, description: SERVICE_ID_DESC
    property :ltype, type: :string, description: LTYPE_DESC, example: LTYPE_EXAMPLE
    property :path, type: :string, description: PATH_DESC, example: PATH_EXAMPLE
    property :data, type: :string, description: DATA_DESC, example: DATA_EXAMPLE
    property :content_type, type: :string, description: CONTENT_TYPE_DESC, example: CONTENT_TYPE_EXAMPLE
    property :name, type: :string, description: NAME_DESC, example: NAME_EXAMPLE
    property :info, type: :string, description: INFO_DESC
    property :module_run_id, type: :integer, format: :int32, description: MODULE_RUN_ID_DESC
    property :created_at, type: :string, format: :date_time, description: Msf::WebServices::Documentation::Api::V1::RootApiDoc::CREATED_AT_DESC
    property :updated_at, type: :string, format: :date_time, description: Msf::WebServices::Documentation::Api::V1::RootApiDoc::UPDATED_AT_DESC
  end

  swagger_path '/api/v1/loots' do
    # Swagger documentation for /api/v1/loots GET
    operation :get do
      key :description, 'Return loot entries that are stored in the database.'
      key :tags, [ 'loot' ]

      parameter :workspace

      response 200 do
        key :description, 'Returns loot data.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :Loot
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

    # Swagger documentation for /api/v1/loots POST
    operation :post do
      key :description, 'Create a loot entry.'
      key :tags, [ 'loot' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the loot.'
        key :required, true
        schema do
          property :workspace, type: :string, required: true, description: Msf::WebServices::Documentation::Api::V1::RootApiDoc::WORKSPACE_POST_DESC, example: Msf::WebServices::Documentation::Api::V1::RootApiDoc::WORKSPACE_POST_EXAMPLE
          property :host, type: :string, format: :ipv4, description: HOST_DESC, example: Msf::WebServices::Documentation::Api::V1::RootApiDoc::HOST_EXAMPLE
          property :service,  '$ref': :Service
          property :ltype, type: :string, description: LTYPE_DESC, example: LTYPE_EXAMPLE, required: true
          property :path, type: :string, description: CREATE_PATH_DESC, example: CREATE_PATH_EXAMPLE, required: true
          property :data, type: :string, description: DATA_DESC, example: DATA_EXAMPLE
          property :ctype, type: :string, description: CONTENT_TYPE_DESC, example: CONTENT_TYPE_EXAMPLE
          property :name, type: :string, description: NAME_DESC, example: NAME_EXAMPLE, required: true
          property :info, type: :string, description: INFO_DESC
        end
      end

      response 200 do
        key :description, Msf::WebServices::Documentation::Api::V1::RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :'$ref', :Loot
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

    # Swagger documentation for /api/v1/loot/ DELETE
    operation :delete do
      key :description, 'Delete the specified loot.'
      key :tags, [ 'loot' ]

      parameter :delete_opts

      response 200 do
        key :description, 'Returns an array containing the successfully deleted loot.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :Loot
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
  end

  swagger_path '/api/v1/loots/{id}' do
    # Swagger documentation for api/v1/loots/:id GET
    operation :get do
      key :description, 'Return specific loot entry that is stored in the database.'
      key :tags, [ 'loot' ]

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of loot to retrieve.'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns loot data.'
        schema do
          property :data do
            key :'$ref', :Loot
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

    # Swagger documentation for /api/v1/loots/{id} PUT
    operation :put do
      key :description, 'Update the attributes on an existing loot.'
      key :tags, [ 'loot' ]

      parameter :update_id

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The updated attributes to overwrite to the loot.'
        key :required, true
        schema do
          property :workspace, type: :string, required: true, description: Msf::WebServices::Documentation::Api::V1::RootApiDoc::WORKSPACE_POST_DESC, example: Msf::WebServices::Documentation::Api::V1::RootApiDoc::WORKSPACE_POST_EXAMPLE
          property :host_id, type: :integer, format: :int32, description: HOST_ID_DESC
          property :service_id, type: :integer, format: :int32, description: SERVICE_ID_DESC
          property :ltype, type: :string, description: LTYPE_DESC, example: LTYPE_EXAMPLE, required: true
          property :path, type: :string, description: CREATE_PATH_DESC, example: CREATE_PATH_EXAMPLE, required: true
          property :ctype, type: :string, description: CONTENT_TYPE_DESC, example: CONTENT_TYPE_EXAMPLE
          property :name, type: :string, description: NAME_DESC, example: NAME_EXAMPLE, required: true
          property :info, type: :string, description: INFO_DESC
        end
      end

      response 200 do
        key :description, Msf::WebServices::Documentation::Api::V1::RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :'$ref', :Loot
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
