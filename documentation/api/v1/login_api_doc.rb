require 'swagger/blocks'

module LoginApiDoc
  include Swagger::Blocks

  CORE_ID_DESC = 'The ID of the Metasploit::Credential::Core object this login is associated with.'
  CORE_DESC = 'The Metasploit::Credential::Core object that corresponds to the credential pair this login attempt used.'
  SERVICE_ID_DESC = 'The ID of the service object that this login was attempted against.'
  ACCESS_LEVEL_DESC = 'A free-form text field that can be used to annotate the access level of this login.'
  ACCESS_LEVEL_EXAMPLE = "'admin', 'sudoer', or 'user'"
  STATUS_DESC = 'The result of the login attempt.'
  LAST_ATTEMPTED_AT_DESC = 'The date and time the login attempt occurred.'
  SERVICE_NAME_DESC = 'The name of the service that the login was attempted against.'
  SERVICE_NAME_EXAMPLE = 'ssh'
  ADDRESS_DESC = 'The IP address of the host/service this login was attempted against.'
  ADDRESS_EXAMPLE = '127.0.0.1'
  PORT_DESC = 'The port the service was listening on.'
  PORT_EXAMPLE = '22'
  PROTOCOL_DESC = 'The protocol the service was using.'
  PROTOCOL_ENUM = [ 'tcp', 'udp' ]
  # Values from lib/metasploit/model/login/status.rb in the metasploit-model repo
  STATUS_ENUM = [
      'Denied Access',
      'Disabled',
      'Incorrect',
      'Locked Out',
      'No Auth Required',
      'Successful',
      'Unable to Connect',
      'Untried'
  ]

# Swagger documentation for Login model
  swagger_schema :Login do
    key :required, [:address, :name]
    property :id, type: :integer, format: :int32, description: RootApiDoc::ID_DESC
    property :core_id, type: :integer, format: :int32, required: true, description: CORE_ID_DESC
    property :service_id, type: :integer, format: :int32, required: true, description: SERVICE_ID_DESC
    property :access_level, type: :string, description: ACCESS_LEVEL_DESC, example: ACCESS_LEVEL_EXAMPLE
    property :status, type: :string, description: STATUS_DESC, required: true, enum: STATUS_ENUM
    property :last_attempted_at, type: :string, format: :date_time, description: LAST_ATTEMPTED_AT_DESC
    property :created_at, type: :string, format: :date_time, description: RootApiDoc::CREATED_AT_DESC
    property :updated_at, type: :string, format: :date_time, description: RootApiDoc::UPDATED_AT_DESC
  end

  swagger_path '/api/v1/logins' do
    # Swagger documentation for /api/v1/logins GET
    operation :get do
      key :description, 'Return logins that are stored in the database.'
      key :tags, [ 'login' ]

      response 200 do
        key :description, 'Returns login data.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :Login
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

    # Swagger documentation for /api/v1/logins POST
    operation :post do
      key :description, 'Create a login.'
      key :tags, [ 'login' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the login.'
        key :required, true
        schema do
          property :workspace_id, type: :integer, format: :int32, required: true, description: RootApiDoc::WORKSPACE_ID_DESC
          property :core, '$ref' => :Credential, required: true, description: CORE_DESC
          property :last_attempted_at, type: :string, format: :date_time, required: true, description: LAST_ATTEMPTED_AT_DESC
          property :address, type: :string, format: :ipv4, required: true, description: ADDRESS_DESC, example: ADDRESS_EXAMPLE
          property :service_name, type: :string, description: SERVICE_NAME_DESC, example: SERVICE_NAME_EXAMPLE
          property :port, type: :int32, format: :int32, description: PORT_DESC, example: PORT_EXAMPLE
          property :protocol, type: :string, description: PROTOCOL_DESC, enum: PROTOCOL_ENUM
          property :status, type: :string, required: true, description: STATUS_DESC, enum: STATUS_ENUM
          property :access_level, type: :string, description: ACCESS_LEVEL_DESC, example: ACCESS_LEVEL_EXAMPLE
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :'$ref', :Login
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

    # Swagger documentation for /api/v1/logins/ DELETE
    operation :delete do
      key :description, 'Delete the specified logins.'
      key :tags, [ 'login' ]

      parameter :delete_opts

      response 200 do
        key :description, 'Returns an array containing the successfully deleted logins.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :Login
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

    end
  end

  swagger_path '/api/v1/logins/{id}' do
    # Swagger documentation for api/v1/logins/:id GET
    operation :get do
      key :description, 'Return specific login that is stored in the database.'
      key :tags, [ 'login' ]

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of login to retrieve.'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns login data.'
        schema do
          property :data do
            key :'$ref', :Login
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

    # Swagger documentation for /api/v1/logins/:id PUT
    operation :put do
      key :description, 'Update the attributes an existing login.'
      key :tags, [ 'login' ]

      parameter :update_id

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The updated attributes to overwrite to the login.'
        key :required, true
        schema do
          key :'$ref', :Login
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :'$ref', :Login
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
