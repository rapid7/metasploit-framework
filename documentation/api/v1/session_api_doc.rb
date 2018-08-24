require 'swagger/blocks'

module SessionApiDoc
  include Swagger::Blocks

# Swagger documentation for sessions model
  swagger_schema :Session do
    key :required, [:id]
    property :id, type: :integer, format: :int32
    property :stype, type: :string
    property :via_exploit, type: :string
    property :via_payload, type: :string
    property :desc, type: :string
    property :port, type: :integer, format: :int32
    property :platform, type: :string
    property :opened_at, type: :string, format: :date_time
    property :closed_at, type: :string, format: :date_time
    property :closed_reason, type: :string
    property :local_id, type: :integer, format: :int32
    property :last_seen, type: :string, format: :date_time
    property :module_run_id, type: :integer, format: :int32
  end

  swagger_path '/api/v1/sessions' do
    # Swagger documentation for /api/v1/sessions GET
    operation :get do
      key :description, 'Return sessions that are stored in the database.'
      key :tags, [ 'session' ]

      parameter :workspace

      response 200 do
        key :description, 'Returns session data.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :Session
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

    # Swagger documentation for /api/v1/sessions POST

    # API based creation of session objects is not yet supported from a user-facing perspective.
    # Once this is implemented in a sensible way we will need to uncomment and update the below doc code.

    # operation :post do
    #   key :description, 'Create a session entry.'
    #   key :tags, [ 'session' ]
    #
    #   parameter do
    #     key :in, :body
    #     key :name, :body
    #     key :description, 'The attributes to assign to the session.'
    #     key :required, true
    #     schema do
    #       key :'$ref', :Session
    #     end
    #   end
    #
    #   response 200 do
    #     key :description, RootApiDoc::DEFAULT_RESPONSE_200
    #     schema do
    #       key :type, :object
    #       key :'$ref', :Session
    #     end
    #   end
    # end
  end

  swagger_path '/api/v1/sessions/{id}' do
    # Swagger documentation for api/v1/sessions/:id GET
    operation :get do
      key :description, 'Return a specific session that is stored in the database.'
      key :tags, [ 'session' ]

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of session to retrieve.'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns session data.'
        schema do
          property :data do
            key :'$ref', :Session
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
