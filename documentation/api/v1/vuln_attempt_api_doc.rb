require 'swagger/blocks'

module VulnAttemptApiDoc
  include Swagger::Blocks

  VULN_ID_DESC = 'The ID of the vuln record associated with this vuln attempt was exploiting.'
  SESSION_ID_DESC = 'The ID of the session record associated with this vuln attempt if it was successful.'
  LOOT_ID_DESC = 'The ID of the loot record associated with this vuln attempt if loot was gathered.'
  ATTEMPTED_AT_DESC = 'The time that this vuln attempt occurred.'
  EXPLOITED_DESC = 'true if the vuln attempt was successful.'
  FAIL_REASON_DESC = 'Short reason why this attempt failed.'
  FAIL_DETAIL_DESC = 'Long details about why this attempt failed.'
  MODULE_DESC = 'Full name of the Metasploit module that was used in this attempt.'
  MODULE_EXAMPLE = 'linux/local/docker_daemon_privilege_escalation'
  USERNAME_DESC = 'The username of the user who made this vuln attempt.'


# Swagger documentation for vuln_attempts model
  swagger_schema :VulnAttempt do
    key :required, [:vuln_id]
    property :id, type: :integer, format: :int32, description: RootApiDoc::ID_DESC
    property :vuln_id, type: :integer, format: :int32, description: VULN_ID_DESC
    property :session_id, type: :integer, format: :int32, description: SESSION_ID_DESC
    property :loot_id, type: :integer, format: :int32, description: LOOT_ID_DESC
    property :attempted_at, type: :string, format: :date_time, description: ATTEMPTED_AT_DESC
    property :exploited, type: :boolean, description: EXPLOITED_DESC
    property :fail_reason, type: :string, description: FAIL_REASON_DESC
    property :fail_detail, type: :string, description: FAIL_DETAIL_DESC
    property :module, type: :string, description: MODULE_DESC, example: MODULE_EXAMPLE
    property :username, type: :string, description: USERNAME_DESC
  end

  swagger_path '/api/v1/vuln-attempts' do
    # Swagger documentation for /api/v1/vuln-attempts GET
    operation :get do
      key :description, 'Return vuln attempts that are stored in the database.'
      key :tags, [ 'vuln_attempt' ]

      parameter :workspace

      response 200 do
        key :description, 'Returns vuln attempt data.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :VulnAttempt
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

    # Swagger documentation for /api/v1/vuln-attempts POST
    operation :post do
      key :description, 'Create a vuln attempt entry.'
      key :tags, [ 'vuln_attempt' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the vuln attempt.'
        key :required, true
        schema do
          property :workspace, type: :string, required: true, description: RootApiDoc::WORKSPACE_POST_DESC, example: RootApiDoc::WORKSPACE_POST_EXAMPLE
          property :vuln_id, type: :integer, format: :int32, description: VULN_ID_DESC
          property :attempted_at, type: :string, format: :date_time, description: ATTEMPTED_AT_DESC
          property :exploited, type: :boolean, description: EXPLOITED_DESC
          property :fail_reason, type: :string, description: FAIL_REASON_DESC
          property :fail_detail, type: :string, description: FAIL_DETAIL_DESC
          property :module, type: :string, description: MODULE_DESC, example: MODULE_EXAMPLE
          property :username, type: :string, description: USERNAME_DESC
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :'$ref', :VulnAttempt
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

  swagger_path '/api/v1/vuln-attempts/{id}' do
    # Swagger documentation for api/v1/vuln-attempts/:id GET
    operation :get do
      key :description, 'Return a specific vuln attempt that is stored in the database.'
      key :tags, [ 'vuln_attempt' ]

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of vuln attempt to retrieve.'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns vuln attempt data.'
        schema do
          property :data do
            key :'$ref', :VulnAttempt
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
