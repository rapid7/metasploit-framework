require 'swagger/blocks'

module DbExportApiDoc
  include Swagger::Blocks

  swagger_path '/api/v1/db-export' do
    # Swagger documentation for /api/v1/db-export GET
    operation :get do
      key :description, 'Create a backup of the database as a file that can be re-imported to restore data.'
      key :tags, [ 'db_export' ]

      parameter :workspace

      parameter do
        key :in, :query
        key :name, :path
        key :required, true
        key :description, 'The location to store the export file.'
      end

      parameter do
        key :in, :query
        key :name, :format
        key :required, true
        key :description, 'The file format to export as. Valid values are \'xml\' and \'pwdump\''
      end

      response 200 do
        key :description, 'A JSON object containing the Base64 encoded backup file.'
        schema do
          property :data do
            property :db_export_file do
              key :type, :string
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
