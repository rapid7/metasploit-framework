require 'swagger/blocks'

module NmapApiDoc
  include Swagger::Blocks

  swagger_path '/api/v1/nmaps' do
    # Swagger documentation for /api/v1/nmaps POST
    operation :post do
      key :description, 'Upload an Nmap XML file to be processed into corresponding Metasploit data objects.'
      key :tags, [ 'nmap' ]

      parameter do
        key :in, :body
        key :name, :body
        key :required, true
        schema do
          property :workspace, type: :string, required: true, description: RootApiDoc::WORKSPACE_POST_EXAMPLE
          property :filename, type: :string, required: true, description: 'The name of the file you are uploading.'
          property :data, type: :string, required: true, description: 'The Base64 encoded contents of the Nmap XML file.'
        end
      end

      response 200 do
        key :description, 'A JSON object containing the Base64 encoded backup file.'
        schema do
          property :db_export_file do
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
