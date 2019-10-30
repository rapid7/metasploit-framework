require 'swagger/blocks'

module UserApiDoc
  include Swagger::Blocks

  USERNAME_DESC = 'The username of the user.'
  USERNAME_EXAMPLE = 'bmoose'
  PASSWORD_DESC = 'The password of the user.'
  PASSWORD_EXAMPLE = 'pass123'
  CRYPTED_PASSWORD_DESC = 'The encrypted password of the user.'
  CRYPTED_PASSWORD_EXAMPLE = '$2a$10$ZOmd0VVkcVLTKW/0Cw0BMeqVITeVN4tPQvRvwBizNyM1NIz45oxda'
  PASSWORD_SALT_DESC = 'The password salt for the user\'s password.'
  PERSISTENCE_TOKEN_DESC = 'The persistence token for the user.'
  PERSISTENCE_TOKEN_EXAMPLE = '1a6347561b72aff163b4c1b8324cfdf9ccca37caa681e29d348677afe0cb56927e2e3ab4dc612723'
  FULLNAME_DESC = 'The user\'s full name.'
  FULLNAME_EXAMPLE = 'Bullwinkle J. Moose'
  EMAIL_DESC = 'The user\'s email address.'
  EMAIL_EXAMPLE = 'bullwinkle_moose@rapid7.com'
  PHONE_DESC = 'The user\'s phone number.'
  PHONE_EXAMPLE = '555-555-5555'
  COMPANY_DESC = 'The user\'s company.'
  COMPANY_EXAMPLE = 'Rapid7'
  PREFS_DESC = 'The user\'s preferences.'
  PREFS_EXAMPLE = {}
  ADMIN_DESC = 'A boolean indicating whether the user is an admin.'
  ADMIN_EXAMPLE = false


# Swagger documentation for User model
  swagger_schema :User do
    key :required, [:username, :password]
    property :id, type: :integer, format: :int32, description: RootApiDoc::ID_DESC
    property :username, type: :string, description: USERNAME_DESC, example: USERNAME_EXAMPLE
    property :crypted_password, type: :string, description: CRYPTED_PASSWORD_DESC, example: CRYPTED_PASSWORD_EXAMPLE
    property :password_salt, type: :string, description: PASSWORD_SALT_DESC
    property :persistence_token, type: :string, description: PERSISTENCE_TOKEN_DESC, example: PERSISTENCE_TOKEN_EXAMPLE
    property :created_at, type: :string, description: RootApiDoc::CREATED_AT_DESC
    property :updated_at, type: :string, description: RootApiDoc::UPDATED_AT_DESC
    property :fullname, type: :string, description: FULLNAME_DESC, example: FULLNAME_EXAMPLE
    property :email, type: :string, description: EMAIL_DESC, example: EMAIL_EXAMPLE
    property :phone, type: :string, description: PHONE_DESC, example: PHONE_EXAMPLE
    property :company, type: :string, description: COMPANY_DESC, example: COMPANY_EXAMPLE
    property :prefs, type: :string, description: PREFS_DESC, example: PREFS_EXAMPLE
    property :admin, type: :string, description: ADMIN_DESC, example: ADMIN_EXAMPLE
  end

  swagger_path '/api/v1/users' do
    # Swagger documentation for /api/v1/users GET
    operation :get do
      key :description, 'Return users that are stored in the database.'
      key :tags, [ 'user' ]

      response 200 do
        key :description, 'Returns user data.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :User
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

    # Swagger documentation for /api/v1/users GET
    operation :post do
      key :description, 'Create a user.'
      key :tags, [ 'user' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the user.'
        key :required, true
        schema do
          property :username, type: :string, required: true, description: USERNAME_DESC, example: USERNAME_EXAMPLE
          property :password, type: :string, required: true, description: PASSWORD_DESC, example: PASSWORD_EXAMPLE
          property :fullname, type: :string, description: FULLNAME_DESC, example: FULLNAME_EXAMPLE
          property :email, type: :string, description: EMAIL_DESC, example: EMAIL_EXAMPLE
          property :phone, type: :string, description: PHONE_DESC, example: PHONE_EXAMPLE
          property :company, type: :string, description: COMPANY_DESC, example: COMPANY_EXAMPLE
          property :prefs, type: :string, description: PREFS_DESC, example: PREFS_EXAMPLE
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :User
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
end
