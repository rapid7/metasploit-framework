require 'json'
require 'swagger/blocks'

# TODO Test data originally based on the Swagger UI example data

RESOURCE_LISTING_JSON_V2 = open(File.expand_path('../swagger_v2_api_declaration.json', __FILE__)).read

class PetControllerV2
  include Swagger::Blocks

  swagger_root host: 'petstore.swagger.wordnik.com' do
    key :swagger, '2.0'
    info version: '1.0.0' do
      key :title, 'Swagger Petstore'
      key :description, 'A sample API that uses a petstore as an example to ' \
                        'demonstrate features in the swagger-2.0 specification'
      key :termsOfService, 'http://helloreverb.com/terms/'
      contact do
        key :name, 'Wordnik API Team'
      end
      license do
        key :name, 'MIT'
      end
    end
    key :basePath, '/api'
    key :schemes, ['http']
    key :consumes, ['application/json']
    key :produces, ['application/json']
    security_definition :api_key, type: :apiKey do
      key :name, :api_key
      key :in, :header
    end
    security_definition :petstore_auth do
      key :type, :oauth2
      key :authorizationUrl, 'http://swagger.io/api/oauth/dialog'
      key :flow, :implicit
      scopes 'write:pets' => 'modify pets in your account' do
        key 'read:pets', 'read your pets'
      end
    end
    externalDocs description: 'Find more info here' do
      key :url, 'https://swagger.io'
    end
    tag name: 'pet' do
      key :description, 'Pets operations'
      externalDocs description: 'Find more info here' do
        key :url, 'https://swagger.io'
      end
    end
    parameter :species do
      key :name, :species
      key :in, :body
      key :description, 'Species of this pet'
      key :type, :string
    end
  end

  swagger_path '/pets' do
    operation :get do
      key :description, 'Returns all pets from the system that the user has access to'
      key :operationId, 'findPets'
      key :produces, [
        'application/json',
        'application/xml',
        'text/xml',
        'text/html',
      ]
      parameter do
        key :name, :tags
        key :in, :query
        key :description, 'tags to filter by'
        key :required, false
        key :type, :array
        items do
          key :type, :string
        end
        key :collectionFormat, :csv
      end
      parameter do
        key :name, :limit
        key :in, :query
        key :description, 'maximum number of results to return'
        key :required, false
        key :type, :integer
        key :format, :int32
      end
      response 200 do
        key :description, 'pet response'
        schema type: :array do
          items do
            key :'$ref', :Pet
          end
        end
      end
      response :default do
        key :description, 'unexpected error'
        schema do
          key :'$ref', :ErrorModel
        end
      end
    end
    operation :post do
      key :description, 'Creates a new pet in the store.  Duplicates are allowed'
      key :operationId, 'addPet'
      key :produces, [
        'application/json'
      ]
      parameter do
        key :name, :pet
        key :in, :body
        key :description, 'Pet to add to the store'
        key :required, true
        schema do
          key :'$ref', :PetInput
        end
      end
      parameter :species
      response 200 do
        key :description, 'pet response'
        schema do
          # Wrong form here, but checks that #/ strings are not transformed.
          key :'$ref', '#/parameters/Pet'
        end
      end
      response :default, description: 'unexpected error' do
        schema do
          key :'$ref', 'http://example.com/schema.json#/definitions/ErrorModel'
        end
      end
    end
  end

  swagger_path '/pets/{id}' do
    parameter do
      key :name, :id
      key :in, :path
      key :description, 'ID of pet'
      key :required, true
      key :type, :integer
      key :format, :int64
    end
    operation :put do
      key :description, 'Update a pet in the store.'
      key :operationId, 'updatePet'
      key :produces, [
        'application/json'
      ]
      parameter do
        key :name, :pet
        key :in, :body
        key :description, 'Pet to update in the store'
        key :required, true
        schema do
          key :'$ref', :PetInput
        end
      end

      parameter :species

      response 200 do
        key :description, 'pet response'
        schema do
          # Wrong form here, but checks that #/ strings are not transformed.
          key :'$ref', '#/parameters/Pet'
        end
      end
      response :default, description: 'unexpected error' do
        schema do
          key :'$ref', 'http://example.com/schema.json#/definitions/ErrorModel'
        end
      end
    end
    operation :get do
      key :description, 'Returns a user based on a single ID, if the user does not have access to the pet'
      key :operationId, 'findPetById'
      key :produces, [
        'application/json',
        'application/xml',
        'text/xml',
        'text/html',
      ]
      response 200 do
        key :description, 'pet response'
        schema do
          key :'$ref', :Pet
        end
      end
      response :default do
        key :description, 'unexpected error'
        schema do
          key :'$ref', :ErrorModel
        end
      end
      security api_key: []
      security do
        key :petstore_auth, ['write:pets', 'read:pets']
      end
    end
    operation :delete do
      key :description, 'deletes a single pet based on the ID supplied'
      key :operationId, 'deletePet'
      response 204 do
        key :description, 'pet deleted'
      end
      response :default do
        key :description, 'unexpected error'
        schema do
          key :'$ref', :ErrorModel
        end
      end
    end
  end

end

class PetV2
  include Swagger::Blocks

  swagger_schema :Pet, required: [:id, :name] do
    property :id do
      key :type, :integer
      key :format, :int64
    end
    property :name do
      key :type, :string
    end
    property :colors do
      key :type, :array
      items do
        key :type, :string
      end
    end
  end

  swagger_schema :PetInput do
    allOf do
      schema do
        key :'$ref', :Pet
      end
      schema do
        key :required, [:name]
        property :id do
          key :type, :integer
          key :format, :int64
        end
        property :name do
          key :type, :string
        end
        property :nestedObject do
          key :type, :object
          property :name do
            key :type, :string
          end
        end
        property :arrayOfObjects do
          key :type, :array
          items do
            key :type, :object
            property :name do
              key :type, :string
            end
            property :age do
              key :type, :integer
            end
          end
        end
        property :arrayOfArrays do
          key :type, :array
          items do
            key :type, :array
            items do
              key :type, :integer
            end
          end
        end
      end
    end
  end
end

class ErrorModelV2
  include Swagger::Blocks

  swagger_schema :ErrorModel do
    key :required, [:code, :message]
    property :code do
      key :type, :integer
      key :format, :int32
    end
    property :message do
      key :type, :string
    end
  end
end

describe 'Swagger::Blocks v2' do
  describe 'build_json' do
    it 'outputs the correct data' do
      swaggered_classes = [
        PetControllerV2,
        PetV2,
        ErrorModelV2
      ]
      actual = Swagger::Blocks.build_root_json(swaggered_classes)
      actual = JSON.parse(actual.to_json)  # For access consistency.
      data = JSON.parse(RESOURCE_LISTING_JSON_V2)

      # Multiple expectations for better test diff output.
      expect(actual['info']).to eq(data['info'])
      expect(actual['paths']).to be
      expect(actual['paths']['/pets']).to be
      expect(actual['paths']['/pets']).to eq(data['paths']['/pets'])
      expect(actual['paths']['/pets/{id}']).to be
      expect(actual['paths']['/pets/{id}']['get']).to be
      expect(actual['paths']['/pets/{id}']['get']).to eq(data['paths']['/pets/{id}']['get'])
      expect(actual['paths']).to eq(data['paths'])
      expect(actual['definitions']).to eq(data['definitions'])
      expect(actual).to eq(data)
    end
    it 'is idempotent' do
      swaggered_classes = [PetControllerV2, PetV2, ErrorModelV2]
      actual = JSON.parse(Swagger::Blocks.build_root_json(swaggered_classes).to_json)
      data = JSON.parse(RESOURCE_LISTING_JSON_V2)
      expect(actual).to eq(data)
    end
    it 'errors if no swagger_root is declared' do
      expect {
        Swagger::Blocks.build_root_json([])
      }.to raise_error(Swagger::Blocks::DeclarationError)
    end
    it 'errors if mulitple swagger_roots are declared' do
      expect {
        Swagger::Blocks.build_root_json([PetControllerV2, PetControllerV2])
      }.to raise_error(Swagger::Blocks::DeclarationError)
    end
  end
end
