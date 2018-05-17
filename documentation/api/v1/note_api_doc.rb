require 'swagger/blocks'

module NoteApiDoc
  include Swagger::Blocks

  TYPE_DESC = 'The type of note this is.'
  TYPE_EXAMPLE = "'host.info', 'host.os.session_fingerprint', 'smb_peer_os', etc."
  CRITICAL_DESC = 'Boolean regarding the criticality of this note\'s contents.'
  SEEN_DESC = 'Boolean regarding if this note has been acknowledged.'
  DATA_DESC = 'The contents of the note.'

# Swagger documentation for notes model
  swagger_schema :Note do
    key :required, [:type]
    property :id, type: :integer, format: :int32
    property :type, type: :string, description: TYPE_DESC, example: TYPE_EXAMPLE
    property :workspace_id, type: :integer, format: :int32
    property :host_id, type: :integer, format: :int32
    property :service_id, type: :integer, format: :int32
    property :critical, type: :boolean, description: CRITICAL_DESC
    property :seen, type: :boolean, description: SEEN_DESC
    property :data, type: :string, description: DATA_DESC
    property :vuln_id, type: :integer, format: :int32
    property :created_at, type: :string, format: :date_time
    property :updated_at, type: :string, format: :date_time
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
          key :type, :array
          items do
            key :'$ref', :Note
          end
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
          property :type, type: :string, description: TYPE_DESC, example: TYPE_EXAMPLE, required: true
          property :workspace, type: :string, required: true
          property :host, type: :integer, format: :int32
          property :critical, type: :boolean, description: CRITICAL_DESC
          property :seen, type: :boolean, description: SEEN_DESC
          property :data, type: :string, description: DATA_DESC
        end
      end

      response 200 do
        key :description, 'Successful operation.'
        schema do
          key :type, :object
          key :'$ref', :Note
        end
      end
    end

    # Swagger documentation for /api/v1/notes/ DELETE
    operation :delete do
      key :description, 'Delete the specified notes.'
      key :tags, [ 'note' ]

      parameter :delete_opts

      response 200 do
        key :description, 'Successful operation.'
        schema do
          key :type, :array
          items do
            key :'$ref', :Note
          end
        end
      end
    end
  end

  swagger_path '/api/v1/notes/{id}' do
    # Swagger documentation for api/v1/notes/:id GET
    operation :get do
      key :description, 'Return specific note that is stored in the database.'
      key :tags, [ 'note' ]

      parameter :workspace

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of note to retrieve.'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns notes data.'
        schema do
          key :type, :array
          items do
            key :'$ref', :Note
          end
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
        key :description, 'Successful operation.'
        schema do
          key :type, :object
          key :'$ref', :Note
        end
      end
    end
  end
end