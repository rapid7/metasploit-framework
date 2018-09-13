require 'swagger/blocks'

module MsfApiDoc
  include Swagger::Blocks

  swagger_path '/api/v1/msf/version' do
    # Swagger documentation for /api/v1/msf/version GET
    operation :get do
      key :description, 'Return the current version of the running Metasploit Framework.'
      key :tags, [ 'msf' ]

      response 200 do
        key :description, 'Returns the Metasploit Framework version.'
        schema do
          property :data do
            property :metasploit_version, type: :string
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
