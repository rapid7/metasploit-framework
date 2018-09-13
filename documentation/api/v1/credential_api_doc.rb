require 'swagger/blocks'

# TODO: Complete this documentation when the credential model is fully implemented in the API.
module CredentialApiDoc
  include Swagger::Blocks

  ORIGIN_ID_DESC = 'The ID of the origin record associated with this credential.'
  ORIGIN_TYPE_DESC = 'The class name within Metasploit::Credential that indicates where this credential came from.'
  PRIVATE_ID_DESC = 'The ID of the Metasploit::Credential::Private record associated with this credential.'
  PUBLIC_ID_DESC = 'The ID of the Metasploit::Credential::Public record associated with this credential.'
  REALM_ID_DESC = 'The ID of the Metasploit::Credential::Realm from where the credential was gathered.'
  LOGINS_COUNT_DESC = 'The number of successful login attempts that were completed using this credential.'
  ADDRESS_DESC = 'The IP address of the host this credential was collected from.'
  ADDRESS_EXAMPLE = '127.0.0.1'
  SERVICE_NAME_DESC = 'The name of the service from which this credential was collected from.'
  SERVICE_NAME_EXAMPLE = 'ssh'
  PORT_DESC = 'The port on which the service was listening where this credential was collected from.'
  PORT_EXAMPLE = '22'
  PROTOCOL_DESC = 'The protocol the service was using.'
  PROTOCOL_ENUM = [ 'tcp', 'udp' ]
  MODULE_FULLNAME_DESC = 'The full name of the Metasploit module that was used to collect this credential.'
  MODULE_FULLNAME_EXAMPLE = 'auxiliary/scanner/smb/smb_login'
  FILENAME_DESC = 'The filename of the file that was imported. This is necessary when the origin_type is import.'
  FILENAME_EXAMPLE = '/etc/shadow'
  POST_REFERENCE_NAME_DESC = 'The reference name of the Metasploit Post module used to collect this credential.'
  POST_REFERENCE_NAME_EXAMPLE = 'post/linux/gather/hashdump'
  SESSION_ID_DESC = 'The ID of the session where this credential was collected from.'
  USERNAME_DESC = 'The username for this credential.'
  USERNAME_EXAMPLE = 'administrator'
  PUBLIC_TYPE_DESC = 'The type of username that this falls into. This is used for searching for similar credentials.'
  PRIVATE_TYPE_DESC = 'The type of password data for this credential.'
  DATA_DESC = 'The private data for this credential.  The semantic meaning of this data varies based on the type.'
  DATA_EXAMPLE = "'password123', '$1$5nfRD/bA$y7ZZD0NimJTbX9FtvhHJX1', or '$NT$7f8fe03093cc84b267b109625f6bbf4b'"
  JTR_FORMAT_DESC = 'Comma-separated list of the formats for John the ripper to use to try and crack this.'
  JTR_FORMAT_EXAMPLE = 'md5,des,bsdi,crypt'
  PUBLIC_TYPE_ENUM = [ 'Metasploit::Credential::BlankUsername', 'Metasploit::Credential::Username' ]
  PRIVATE_TYPE_CLASS_ENUM = [
      'Metasploit::Credential::ReplayableHash',
      'Metasploit::Credential::NonreplayableHash',
      'Metasploit::Credential::NTLMHash',
      'Metasploit::Credential::Password',
      'Metasploit::Credential::PasswordHash',
      'Metasploit::Credential::SSHKey',
      'Metasploit::Credential::PostgresMD5',
      'Metasploit::Credential::BlankPassword'
  ]
  PRIVATE_TYPE_ENUM = [
      'password',
      'ssh_key',
      'ntlm_hash',
      'postgres_md5',
      'nonreplayable_hash',
      '<blank>'
  ]
  ORIGIN_TYPE_CLASS_ENUM = [
      'Metasploit::Credential::Origin::Import',
      'Metasploit::Credential::Origin::Manual',
      'Metasploit::Credential::Origin::Service',
      'Metasploit::Credential::Origin::Session'
  ]
  ORIGIN_TYPE_ENUM = [
      'import',
      'manual',
      'service',
      'session'
  ]


# Swagger documentation for Credential model
  swagger_schema :Credential do
    key :required, [:origin_id]
    property :id, type: :integer, format: :int32, description: RootApiDoc::ID_DESC
    property :origin_id, type: :integer, format: :int32, description: ORIGIN_ID_DESC
    property :origin_type, type: :string, description: ORIGIN_TYPE_DESC, enum: ORIGIN_TYPE_CLASS_ENUM
    property :private_id, type: :integer, format: :int32, description: PRIVATE_ID_DESC
    property :public_id, type: :integer, format: :int32, description: PUBLIC_ID_DESC
    property :realm_id, type: :integer, format: :int32, description: REALM_ID_DESC
    property :workspace_id, type: :integer, format: :int32, required: true, description: RootApiDoc::WORKSPACE_ID_DESC
    property :logins_count, type: :integer, format: :int32, description: LOGINS_COUNT_DESC
    property :logins do
      key :type, :array
      items do
        key :'$ref', :Login
      end
    end
    property :public, '$ref': :Public
    property :private, '$ref': :Private
    property :created_at, type: :string, format: :date_time, description: RootApiDoc::CREATED_AT_DESC
    property :updated_at, type: :string, format: :date_time, description: RootApiDoc::UPDATED_AT_DESC
  end

  swagger_schema :Public do
    key :required, [:username, :type]
    property :id, type: :integer, format: :int32, description: RootApiDoc::ID_DESC
    property :username, type: :string, description: USERNAME_DESC, example: USERNAME_EXAMPLE
    property :type, type: :string, description: PUBLIC_TYPE_DESC, enum: PUBLIC_TYPE_ENUM
    property :created_at, type: :string, format: :date_time, description: RootApiDoc::CREATED_AT_DESC
    property :updated_at, type: :string, format: :date_time, description: RootApiDoc::UPDATED_AT_DESC
  end

  swagger_schema :Private do
    key :required, [:data, :type]
    property :id, type: :integer, format: :int32, description: RootApiDoc::ID_DESC
    property :data, type: :string, description: DATA_DESC, example: DATA_EXAMPLE
    property :type, type: :string, description: PRIVATE_TYPE_DESC, enum: PRIVATE_TYPE_CLASS_ENUM
    property :jtr_format, type: :string, description: JTR_FORMAT_DESC, example: JTR_FORMAT_EXAMPLE
    property :created_at, type: :string, format: :date_time, description: RootApiDoc::CREATED_AT_DESC
    property :updated_at, type: :string, format: :date_time, description: RootApiDoc::UPDATED_AT_DESC
  end

  swagger_path '/api/v1/credentials' do
    # Swagger documentation for /api/v1/credentials GET
    operation :get do
      key :description, 'Return credentials that are stored in the database.'
      key :tags, [ 'credential' ]

      parameter :workspace

      parameter do
        key :in, :query
        key :name, :svcs
        key :description, 'Only return credentials of the specified service.'
        key :example, ['ssh', 'owa', 'smb']
        key :type, :array
        key :required, false
        items do
          key :type, :string
        end
      end

      parameter do
        key :in, :query
        key :name, :type
        key :description, 'The type of credential to return.'
        key :type, :string
        key :required, false
        key :enum, PRIVATE_TYPE_CLASS_ENUM
      end

      parameter do
        key :in, :query
        key :name, :user
        key :description, 'Only return credentials where the user matches this regex.'
        key :example, 'administrator'
        key :type, :string
        key :required, false
      end

      parameter do
        key :in, :query
        key :name, :pass
        key :description, 'Only return credentials where the password matches this regex.'
        key :example, 'password123'
        key :type, :string
        key :required, false
      end

      response 200 do
        key :description, 'Returns credential data.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :Credential
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

    # Swagger documentation for /api/v1/credentials POST
    operation :post do
      key :description, 'Create a credential.'
      key :tags, [ 'credential' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the credential.'
        key :required, true
        schema do
          property :workspace_id, type: :integer, format: :int32, required: true, description: RootApiDoc::WORKSPACE_ID_DESC
          property :username, type: :string, description: USERNAME_DESC, example: USERNAME_EXAMPLE
          property :private_data, type: :string, description: DATA_DESC, example: DATA_EXAMPLE
          property :private_type, type: :string, description: PRIVATE_TYPE_DESC, enum: PRIVATE_TYPE_ENUM
          property :jtr_format, type: :string, description: JTR_FORMAT_DESC, example: JTR_FORMAT_EXAMPLE
          property :address, type: :string, format: :ipv4, required: true, description: ADDRESS_DESC, example: ADDRESS_EXAMPLE
          property :port, type: :int32, format: :int32, description: PORT_DESC, example: PORT_EXAMPLE
          property :service_name, type: :string, description: SERVICE_NAME_DESC, example: SERVICE_NAME_EXAMPLE
          property :protocol, type: :string, description: PROTOCOL_DESC, enum: PROTOCOL_ENUM
          property :origin_type, type: :string, description: ORIGIN_TYPE_DESC, enum: ORIGIN_TYPE_ENUM
          property :module_fullname, type: :string, description: MODULE_FULLNAME_DESC, example: MODULE_FULLNAME_EXAMPLE
          property :filename, type: :string, description: FILENAME_DESC, example: FILENAME_EXAMPLE
          property :session_id, type: :integer, format: :int32, description: SESSION_ID_DESC
          property :post_reference_name, type: :string, description: POST_REFERENCE_NAME_DESC, example: POST_REFERENCE_NAME_EXAMPLE
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :'$ref', :Credential
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

    # Swagger documentation for /api/v1/credentials/ DELETE
    operation :delete do
      key :description, 'Delete the specified credentials.'
      key :tags, [ 'credential' ]

      parameter :delete_opts

      response 200 do
        key :description, 'Returns an array containing the successfully deleted credentials.'
        schema do
          key :type, :array
          items do
            key :'$ref', :Credential
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

  swagger_path '/api/v1/credentials/{id}' do
    # Swagger documentation for api/v1/credentials/:id GET
    operation :get do
      key :description, 'Return credential that is stored in the database.'
      key :tags, [ 'credential' ]

      parameter :workspace
      parameter :non_dead
      parameter :address

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of credential to retrieve.'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns credential data.'
        schema do
          property :data do
            key :'$ref', :Credential
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

    #Swagger documentation for /api/v1/credentials/:id PUT
    operation :put do
      key :description, 'Update the attributes an existing credential.'
      key :tags, [ 'credential' ]

      parameter :update_id

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The updated attributes to overwrite to the credential.'
        key :required, true
        schema do
          key :'$ref', :Credential
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :'$ref', :Credential
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
