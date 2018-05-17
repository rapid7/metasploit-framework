require 'swagger/blocks'

module VulnApiDoc
  include Swagger::Blocks

  HOST_DESC = 'The host where this vuln was discovered.'
  HOST_EXAMPLE = '127.0.0.1'
  NAME_DESC = 'The friendly name/title for this vulnerability.'
  NAME_EXAMPLE = 'Docker Daemon Privilege Escalation'
  INFO_DESC = 'Information about how this vuln was discovered.'
  INFO_EXAMPLE = 'Exploited by exploit/linux/local/docker_daemon_privilege_escalation to create session.'
  REFS_DESC = 'An array of public reference IDs for this vuln.'
  REFS_EXAMPLE = ['CVE-2008-4250','OSVDB-49243','MSB-MS08-067']

# Swagger documentation for vulns model
  swagger_schema :Vuln do
    key :required, [:host_id, :name]
    property :id, type: :integer, format: :int32
    property :host_id, type: :integer, format: :int32
    property :name, type: :string, description: NAME_DESC, example: NAME_EXAMPLE
    property :info, type: :string, description: INFO_DESC, example: INFO_EXAMPLE
    property :exploited_at, type: :string, format: :date_time
    property :vuln_detail_count, type: :integer, format: :int32
    property :vuln_attempt_count, type: :integer, format: :int32
    property :origin_id, type: :integer, format: :int32
    property :origin_type, type: :integer, format: :int32
    property :vuln_refs do
      key :type, :array
      items do
        key :'$ref', :VulnRef
      end
    end
    property :refs do
      key :type, :array
      items do
        key :'$ref', :Ref
      end
    end
    property :module_refs do
      key :type, :array
      items do
        key :'$ref', :ModuleRef
      end
    end
    property :created_at, type: :string, format: :date_time
    property :updated_at, type: :string, format: :date_time
  end

  swagger_schema :Ref do
    key :required, [:name]
    property :id, type: :integer, format: :int32
    property :ref_id, type: :integer, format: :int32
    property :name, type: :string, required: true
    property :created_at, type: :string, format: :date_time
    property :updated_at, type: :string, format: :date_time
  end

  swagger_schema :ModuleRef do
    key :required, [:name]
    property :id, type: :integer, format: :int32
    property :detail_id, type: :integer, format: :int32
    property :name, type: :string, required: true
  end

  swagger_schema :VulnRef do
    key :required, [:ref_id, :vuln_id]
    property :id, type: :integer, format: :int32
    property :ref_id, type: :integer, format: :int32
    property :vuln_id, type: :integer, format: :int32
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
          key :type, :array
          items do
            key :'$ref', :Vuln
          end
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
          property :workspace, type: :string, required: true
          property :host, type: :string, format: :ipv4, required: true, description: HOST_DESC, example: HOST_EXAMPLE
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
        key :description, 'Successful operation.'
        schema do
          key :type, :object
          key :'$ref', :Vuln
        end
      end
    end

    # Swagger documentation for /api/v1/vulns/ DELETE
    operation :delete do
      key :description, 'Delete the specified vulns.'
      key :tags, [ 'vuln' ]

      parameter :delete_opts

      response 200 do
        key :description, 'Successful operation.'
        schema do
          key :type, :array
          items do
            key :'$ref', :Vuln
          end
        end
      end
    end
  end

  swagger_path '/api/v1/vulns/{id}' do
    # Swagger documentation for api/v1/vulns/:id GET
    operation :get do
      key :description, 'Return specific vuln that is stored in the database.'
      key :tags, [ 'vuln' ]

      parameter :workspace

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
          key :type, :array
          items do
            key :'$ref', :Vuln
          end
        end
      end
    end

    # Swagger documentation for /api/v1/vulns/:id PUT
    operation :put do
      key :description, 'Update the attributes an existing vuln.'
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
        key :description, 'Successful operation.'
        schema do
          key :type, :object
          key :'$ref', :Vuln
        end
      end
    end
  end
end