require 'swagger/blocks'

module AuthApiDoc
  include Swagger::Blocks

  MESSAGE_DESC = 'The status of the authentication request.'
  MESSAGE_EXAMPLE = 'Generated new API token.'
  TOKEN_DESC = 'The Authentication Bearer token'
  TOKEN_EXAMPLE = '899d2f45e12429d07427230289400a4594bcffe32169ebb826b4ffa9b90e1d1586f15fa42f069bb7'

  # Swagger documentation for auth model
  swagger_schema :Auth do
    property :message, type: :string, description: MESSAGE_DESC, example: MESSAGE_EXAMPLE
    property :token, type: :string, description: TOKEN_DESC, example: TOKEN_EXAMPLE
  end

  swagger_path '/api/v1/auth/generate-token' do
    # Swagger documentation for /api/v1/auth/generate-token POST
    operation :post do

      key :description, 'Return a valid Authorization Bearer token.'
      key :tags, [ 'auth' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'Login credentials for the user who will be generating a token.'
        key :required, true
        schema do
          property :username, type: :string, required: true
          property :password, type: :string, required: true
        end
      end

      response 200 do
        key :description, 'Returns a valid auth token.'
        schema do
          property :data do
            key :'$ref', :Auth
          end
        end
      end

      response 401 do
        key :description, 'Invalid username or password. ' + RootApiDoc::DEFAULT_RESPONSE_401
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
