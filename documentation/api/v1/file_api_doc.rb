require 'swagger/blocks'

module FileApiDoc
  include Swagger::Blocks

  FILE_DESC = 'Specify a file.'.freeze
  PATH_DESC = 'Specify a path.'.freeze

  # Swagger documentation for File model
  swagger_schema :File do
    property :path, type: :string, description: FILE_DESC
  end

  swagger_path '/api/v1/files/file' do
    # Swagger documentation for /api/v1/files/file GET
    operation :get do
      key :description, 'Download the file in the specified path.'
      key :tags, [ 'file' ]

      parameter do
        key :in, :query
        key :name, :path
        key :required, true
        key :description, FILE_DESC
      end

      response 200 do
        key :description, 'Return downloaded file.'
        schema do
          property :data do
            key :type, :string
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

    # Swagger documentation for /api/v1/files/file POST
    operation :post do
      key :description, 'Upload file to the specified path.'
      key :tags, [ 'file' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'Specify a path.'
        key :required, true
        schema do
          property :path, type: :string, required: true, description: FILE_DESC
          property :file, type: :string, format: :binary, required: true, description: 'Please upload a file'
        end
      end

      response 200 do
        key :description, 'Return the path of the file'
        schema do
          property :data do
            key :type, :string
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
    # Swagger documentation for /api/v1/files/file PUT
    operation :put do
      key :description, 'Rename the file at the specified path.'
      key :tags, [ 'file' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'Original file path.'
        key :required, true
        schema do
          property :path, type: :string, required: true, description: FILE_DESC
          property :new_path, type: :string, required: true, description: FILE_DESC
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :type, :string
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
    # Swagger documentation for /api/v1/files/file DELETE
    operation :delete do
      key :description, 'Delete the file in the specified path.'
      key :tags, [ 'file' ]

      parameter do
        key :in, :body
        key :name, :path
        key :description, FILE_DESC
        key :required, true
        schema do
          property :path, type: :string, required: true, description: FILE_DESC
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :type, :string
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

  swagger_path '/api/v1/files/dir' do
    # Swagger documentation for api/v1/files/dir GET
    operation :get do
      key :description, 'List the files in the specified path.'
      key :tags, [ 'file' ]

      parameter do
        key :name, :path
        key :in, :query
        key :description, 'Specify a directory.'
        key :required, false
      end

      response 200 do
        key :description, 'Returns file data.'
        schema do
          property :data do
            key :type, :string
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

    # Swagger documentation for api/v1/files/dir POST
    operation :post do
      key :description, 'Create a directory to the specified path.'
      key :tags, [ 'file' ]

      parameter do
        key :name, :body
        key :in, :body
        key :description, 'Specify a directory.'
        key :required, true
        schema do
          property :path, type: :string, required: true, description: FILE_DESC
        end
      end

      response 200 do
        key :description, 'Return to the successfully created path.'
        schema do
          property :data do
            key :type, :string
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

    # Swagger documentation for /api/v1/hosts/:id PUT
    operation :put do
      key :description, 'Rename the specified directory.'
      key :tags, [ 'file' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'Original directory path.'
        key :required, true
        schema do
          property :path, type: :string, required: true, description: FILE_DESC
          property :new_path, type: :string, required: true, description: FILE_DESC
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :type, :string
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
    # Swagger documentation for /api/v1/hosts/:id DELETE
    operation :delete do
      key :description, 'Delete the specified path directory.'
      key :tags, [ 'file' ]

      parameter do
        key :in, :body
        key :name, :path
        key :description, 'Specify a directory.'
        key :required, true
        schema do
          property :path, type: :string, required: true, description: FILE_DESC
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :type, :string
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
  swagger_path '/api/v1/files/root' do
    # Swagger documentation for api/v1/files/root GET
    operation :get do
      key :description, 'Return rest_file directory path.'
      key :tags, [ 'file' ]

      response 200 do
        key :description, 'Return rest_file directory path.'
        schema do
          property :data do
            key :type, :string
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
  swagger_path '/api/v1/files/search' do
    # Swagger documentation for api/v1/files/search GET
    operation :get do
      key :description, 'Return search keywords file path.'
      key :tags, [ 'file' ]
      parameter do
        key :in, :query
        key :name, :path
        key :description, PATH_DESC
      end
      parameter do
        key :in, :query
        key :name, :search_term
        key :description, 'search keywords'
      end
      response 200 do
        key :description, 'Returns file data.'
        schema do
          property :data do
            key :type, :string
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
