require 'swagger/blocks'

module NoteApiDoc
  include Swagger::Blocks

  NTYPE_DESC = 'The type of note this is.'
  NTYPE_EXAMPLE = "'host.info', 'host.os.session_fingerprint', 'smb_peer_os', etc."
  HOST_ID_DESC = 'The ID of the host record this note is associated with.'
  HOST_DESC = 'The IP address of the host this note is associated with.'
  SERVICE_ID_DESC = 'The ID of the host record this service is associated with.'
  VULN_ID_DESC = 'The ID of the host record this note is associated with.'
  CRITICAL_DESC = 'Boolean regarding the criticality of this note\'s contents.'
  SEEN_DESC = 'Boolean regarding if this note has been acknowledged.'
  DATA_DESC = 'The contents of the note.'

# Swagger documentation for notes model
  swagger_schema :Note do
    key :required, [:ntype]
    property :id, type: :integer, format: :int32, description: RootApiDoc::ID_DESC
    property :ntype, type: :string, description: NTYPE_DESC, example: NTYPE_EXAMPLE
    property :workspace_id, type: :integer, format: :int32, description: RootApiDoc::WORKSPACE_ID_DESC
    property :host_id, type: :integer, format: :int32, description: HOST_ID_DESC
    property :service_id, type: :integer, format: :int32, description: SERVICE_ID_DESC
    property :vuln_id, type: :integer, format: :int32, description: VULN_ID_DESC
    property :critical, type: :boolean, description: CRITICAL_DESC
    property :seen, type: :boolean, description: SEEN_DESC
    property :data, type: :string, description: DATA_DESC
    property :created_at, type: :string, format: :date_time, description: RootApiDoc::CREATED_AT_DESC
    property :updated_at, type: :string, format: :date_time, description: RootApiDoc::UPDATED_AT_DESC
  end

  swagger_path '/api/v1/notes' do
    # Swagger documentation for /api/v1/notes GET
    operation :get do
      key :description, 'Return notes that are stored in the database.'
      key :tags, [ 'note' ]

      parameter :workspace

      response 200 do
        key :description, 'Returns note data.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :Note
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

    # Swagger documentation for /api/v1/notes POST
    operation :post do
      key :description, 'Create a note entry.'
      key :tags, [ 'note' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the note.'
        key :required, true
        schema do
          property :ntype, type: :string, description: NTYPE_DESC, example: NTYPE_EXAMPLE, required: true
          property :workspace, type: :string, required: true, description: RootApiDoc::WORKSPACE_POST_DESC, example: RootApiDoc::WORKSPACE_POST_EXAMPLE
          property :host, type: :integer, format: :ipv4, description: HOST_DESC, example: RootApiDoc::HOST_EXAMPLE
          property :critical, type: :boolean, description: CRITICAL_DESC
          property :seen, type: :boolean, description: SEEN_DESC
          property :data, type: :string, description: DATA_DESC
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :'$ref', :Note
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

    # Swagger documentation for /api/v1/notes/ DELETE
    operation :delete do
      key :description, 'Delete the specified notes.'
      key :tags, [ 'note' ]

      parameter :delete_opts

      response 200 do
        key :description, 'Returns an array containing the successfully deleted notes.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :Note
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

  swagger_path '/api/v1/notes/{id}' do
    # Swagger documentation for api/v1/notes/:id GET
    operation :get do
      key :description, 'Return specific note that is stored in the database.'
      key :tags, [ 'note' ]

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of note to retrieve.'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns note data.'
        schema do
          property :data do
            key :'$ref', :Note
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

    # Swagger documentation for /api/v1/notes/:id PUT
    operation :put do
      key :description, 'Update the attributes an existing note.'
      key :tags, [ 'note' ]

      parameter :update_id

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The updated attributes to overwrite to the note.'
        key :required, true
        schema do
          key :'$ref', :Note
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :'$ref', :Note
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
