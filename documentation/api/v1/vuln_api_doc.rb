require 'swagger/blocks'

module VulnApiDoc
  include Swagger::Blocks

  HOST_ID_DESC = 'The ID of host record associated with this vuln.'
  HOST_DESC = 'The host where this vuln was discovered.'
  NAME_DESC = 'The friendly name/title for this vulnerability.'
  NAME_EXAMPLE = 'Docker Daemon Privilege Escalation'
  INFO_DESC = 'Information about how this vuln was discovered.'
  INFO_EXAMPLE = 'Exploited by exploit/linux/local/docker_daemon_privilege_escalation to create session.'
  EXPLOITED_AT_DESC = 'The date and time this vuln was successfully exploited.'
  VULN_DETAIL_COUNT = 'Cached count of the number of associated vuln detail objects.'
  VULN_ATTEMPT_COUNT = 'Cached count of the number of associated vuln attempt object.'
  ORIGIN_ID_DESC = 'ID of the associated origin record.'
  ORIGIN_TYPE_DESC = 'The origin type of this vuln.'
  REFS_DESC = 'An array of public reference IDs for this vuln.'
  REF_ID_DESC = 'The ID of the related Mdm::Ref associated with this vuln.'
  REF_NAME_DESC = 'Designation for external reference.  May include a prefix for the authority, such as \'CVE-\', in which case the rest of the name is the designation assigned by that authority.'
  REFS_EXAMPLE = ['CVE-2008-4250','OSVDB-49243','MSB-MS08-067']

# Swagger documentation for vulns model
  swagger_schema :Vuln do
    key :required, [:host_id, :name]
    property :id, type: :integer, format: :int32, description: RootApiDoc::ID_DESC
    property :host_id, type: :integer, format: :int32, description: HOST_ID_DESC
    property :name, type: :string, description: NAME_DESC, example: NAME_EXAMPLE
    property :info, type: :string, description: INFO_DESC, example: INFO_EXAMPLE
    property :exploited_at, type: :string, format: :date_time, description: EXPLOITED_AT_DESC
    property :vuln_detail_count, type: :integer, format: :int32, description: VULN_DETAIL_COUNT
    property :vuln_attempt_count, type: :integer, format: :int32, description: VULN_ATTEMPT_COUNT
    property :origin_id, type: :integer, format: :int32, description: ORIGIN_ID_DESC
    property :origin_type, type: :string, description: ORIGIN_TYPE_DESC
    property :refs do
      key :type, :array
      items do
        key :'$ref', :Ref
      end
    end
    property :created_at, type: :string, format: :date_time, description: RootApiDoc::CREATED_AT_DESC
    property :updated_at, type: :string, format: :date_time, description: RootApiDoc::UPDATED_AT_DESC
  end

  swagger_schema :Ref do
    key :required, [:name]
    property :id, type: :integer, format: :int32, description: RootApiDoc::ID_DESC
    property :ref_id, type: :integer, format: :int32, description: REF_ID_DESC
    property :name, type: :string, required: true, description: REF_NAME_DESC
    property :created_at, type: :string, format: :date_time, description: RootApiDoc::CREATED_AT_DESC
    property :updated_at, type: :string, format: :date_time, description: RootApiDoc::UPDATED_AT_DESC
  end

  swagger_path '/api/v1/vulns' do
    # Swagger documentation for /api/v1/vulns GET
    operation :get do
      key :description, 'Return vulns that are stored in the database.'
      key :tags, [ 'vuln' ]

      parameter :workspace

      response 200 do
        key :description, 'Returns vuln data.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :Vuln
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

    # Swagger documentation for /api/v1/vulns POST
    operation :post do
      key :description, 'Create a vuln entry.'
      key :tags, [ 'vuln' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the vuln.'
        key :required, true
        schema do
          property :workspace, type: :string, required: true, description: RootApiDoc::WORKSPACE_POST_DESC, example: RootApiDoc::WORKSPACE_POST_EXAMPLE
          property :host, type: :string, format: :ipv4, required: true, description: HOST_DESC, example: RootApiDoc::HOST_EXAMPLE
          property :name, type: :string, description: NAME_DESC, example: NAME_EXAMPLE
          property :info, type: :string, description: INFO_DESC, example: INFO_EXAMPLE
          property :refs do
            key :type, :array
            key :description, REFS_DESC
            key :example, REFS_EXAMPLE
            items do
              key :type, :string
            end
          end
        end
      end

      response 200 do
        key :description, 'Returns vuln data.'
        schema do
          property :data do
            key :'$ref', :Vuln
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

    # Swagger documentation for /api/v1/vulns/ DELETE
    operation :delete do
      key :description, 'Delete the specified vulns.'
      key :tags, [ 'vuln' ]

      parameter :delete_opts

      response 200 do
        key :description, 'Returns an array containing the successfully deleted vulns.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :Vuln
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

  swagger_path '/api/v1/vulns/{id}' do
    # Swagger documentation for api/v1/vulns/:id GET
    operation :get do
      key :description, 'Return specific vuln that is stored in the database.'
      key :tags, [ 'vuln' ]

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of vuln to retrieve.'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns vuln data.'
        schema do
          property :data do
            key :'$ref', :Vuln
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

    # Swagger documentation for /api/v1/vulns/:id PUT
    operation :put do
      key :description, 'Update the attributes on an existing vuln.'
      key :tags, [ 'vuln' ]

      parameter :update_id

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The updated attributes to overwrite to the vuln.'
        key :required, true
        schema do
          key :'$ref', :Vuln
        end
      end

      response 200 do
        key :description, 'Returns vuln data.'
        schema do
          property :data do
            key :'$ref', :Vuln
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
