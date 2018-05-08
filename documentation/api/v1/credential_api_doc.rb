require 'swagger/blocks'

module CredentialApiDoc
  include Swagger::Blocks

# Swagger documentation for Credential model
  swagger_schema :Credential do
    key :required, [:id, :name]
    property :id, type: :integer, format: :int32
    property :created_at, type: :string, format: :date_time
    property :updated_at, type: :string, format: :date_time
    property :origin_id, type: :integer, format: :int32
    property :origin_type, type: :string
    property :private_id, type: :integer, format: :int32
    property :public_id, type: :integer, format: :int32
    property :realm_id, type: :integer, format: :int32
    property :workspace_id, type: :integer, format: :int32
    property :logins_count, type: :integer, format: :int32
    property :logins do
      key :type, :array
      items do
      end
    end
  end

  swagger_path '/api/v1/credentials' do
    # Swagger documentation for /api/v1/credentials GET
    operation :get do
      key :description, 'Return credentials that are stored in the database.'
      key :tags, [ 'credential' ]

      parameter do
        key :in, :body
        key :name, :body
        key :required, true
        schema do
          property :workspace do
            key :in, :body
            key :description, 'The workspace from which to return credentials.'
            key :type, :string
            key :required, true
          end

          property :svcs do
            key :in, :body
            key :description, 'Only return credentials of the specified service.'
            key :type, :array
            key :required, false
            items do
              key :type, :string
            end
          end

          property :ptype do
            key :in, :body
            key :description, 'The type of credential to return.'
            key :type, :string
            key :required, false
            key :enum, ['password','ntlm','hash']
          end

          property :user do
            key :in, :body
            key :description, 'Only return credentials where the user matches this regex.'
            key :type, :string
            key :required, false
          end

          property :pass do
            key :in, :body
            key :description, 'Only return credentials where the password matches this regex.'
            key :type, :string
            key :required, false
          end
        end
      end

      response 200 do
        key :description, 'Returns credential data'
        schema do
          key :type, :array
          items do
            key :'$ref', :Credential
          end
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
        key :description, 'The attributes to assign to the credential'
        key :required, true
        schema do
          key :'$ref', :Credential
        end
      end

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :object
          key :'$ref', :Credential
        end
      end
    end

    # This endpoint is NYI.
    #
    # # Swagger documentation for /api/v1/credentials/ DELETE
    # operation :delete do
    #   key :description, 'Delete the specified credentials.'
    #   key :tags, [ 'credential' ]
    #
    #   parameter :delete_opts
    #
    #   response 200 do
    #     key :description, 'Successful operation'
    #     schema do
    #       key :type, :array
    #       items do
    #         key :'$ref', :Credential
    #       end
    #     end
    #   end
    # end
  end

  # This endpoint is NYI.
  #
  # swagger_path '/api/v1/credentials/:id' do
  #   # Swagger documentation for api/v1/credentials/:id GET
  #   operation :get do
  #     key :description, 'Return credentials that are stored in the database.'
  #     key :tags, [ 'credential' ]
  #
  #     parameter :workspace
  #     parameter :non_dead
  #     parameter :address
  #
  #     parameter do
  #       key :name, :id
  #       key :in, :path
  #       key :description, 'ID of credential to retrieve'
  #       key :required, true
  #       key :type, :integer
  #       key :format, :int32
  #     end
  #
  #     response 200 do
  #       key :description, 'Returns credential data'
  #       schema do
  #         key :type, :array
  #         items do
  #           key :'$ref', :Credential
  #         end
  #       end
  #     end
  #   end

  # This endpoint is NYI.
  #
  # Swagger documentation for /api/v1/credentials/:id PUT
  # operation :put do
  #   key :description, 'Update the attributes an existing credential.'
  #   key :tags, [ 'credential' ]
  #
  #   parameter :update_id
  #
  #   parameter do
  #     key :in, :body
  #     key :name, :body
  #     key :description, 'The updated attributes to overwrite to the credential'
  #     key :required, true
  #     schema do
  #       key :'$ref', :Credential
  #     end
  #   end
  #
  #   response 200 do
  #     key :description, 'Successful operation'
  #     schema do
  #       key :type, :object
  #       key :'$ref', :Credential
  #     end
  #   end
  # end
  #end
end