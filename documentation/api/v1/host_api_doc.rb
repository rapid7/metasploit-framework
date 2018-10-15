require 'swagger/blocks'

module HostApiDoc
  include Swagger::Blocks

  HOST_DESC = 'The IP address of the host.'
  HOST_EXAMPLE = '127.0.0.1'
  MAC_DESC = 'MAC Address of the host'
  MAC_EXAMPLE = 'AA:BB:CC:11:22:33'
  COMM_DESC = 'Unused attribute.'
  NAME_DESC = 'Hostname of the host.'
  NAME_EXAMPLE = 'domain_controller'
  STATE_DESC = 'The last seen connectivity state of this host.'
  OS_NAME_DESC = 'The name of the operating system.'
  OS_NAME_EXAMPLE = "'Windows XP', 'Ubuntu', or 'Mac OS X'"
  OS_FLAVOR_DESC = 'The flavor of operating system.'
  OS_FLAVOR_EXAMPLE = "'Enterprise', 'Pro', or 'Home'"
  OS_SP_DESC = 'The service pack version the operating system is running.'
  OS_SP_EXAMPLE = "'SP2'"
  OS_LANG_DESC = 'The language the operating system is using.'
  OS_LANG_EXAMPLE = "'English', 'French', or 'en-US'"
  OS_FAMILY_DESC = 'The major family the operating system belongs to.'
  OS_FAMILY_EXAMPLE = "'Windows', 'Linux', or 'OS X'"
  ARCH_DESC = 'The architecture of the host\'s CPU OR the programming language for virtual machine programming language like Ruby, PHP, and Java.'
  DETECTED_ARCH_DESC = 'The architecture of the host\'s CPU as detected by `Recog`. If arch is not \'unknown\', this is undefined.'
  PURPOSE_DESC = 'The main function of the host.'
  INFO_DESC = 'Customizable information about the host.'
  COMMENTS_DESC = 'A place for storing notes or findings about the host.'
  SCOPE_DESC = 'Interface identifier for link-local IPv6.'
  VIRTUAL_HOST_DESC = 'The name of the virtualization software.'
  VIRTUAL_HOST_EXAMPLE = "'VMWare', 'QEMU', 'Xen', or 'Docker'"
  NOTE_COUNT_DESC = 'Cached count of the number of associated notes.'
  VULN_COUNT_DESC = 'Cached count of the number of associated vulns.'
  SERVICE_COUNT_DESC = 'Cached count of the number of associated services.'
  HOST_DETAIL_COUNT_DESC = 'Cached count of the number of associated host details.'
  EXPLOIT_ATTEMPT_COUNT_DESC = 'Cached count of the number of associated exploit attempts.'
  CRED_COUNT_DESC = 'Cached count of the number of associated creds.'
  STATE_ENUM = [ 'alive', 'down', 'unknown' ]
  ARCH_ENUM = [
      'armbe',
      'armle',
      'cbea',
      'cbea64',
      'cmd',
      'java',
      'mips',
      'mipsbe',
      'mipsle',
      'php',
      'ppc',
      'ppc64',
      'ruby',
      'sparc',
      'tty',
      'x64',
      'x86',
      'x86_64',
      '',
      'Unknown'
  ]

# Swagger documentation for Host model
  swagger_schema :Host do
    key :required, [:address, :name]
    property :id, type: :integer, format: :int32, description: RootApiDoc::ID_DESC
    property :address, type: :string, description: HOST_DESC, example: HOST_EXAMPLE
    property :mac, type: :string, description: MAC_DESC, example: MAC_EXAMPLE
    property :comm, type: :string, description: COMM_DESC
    property :name, type: :string, description: NAME_DESC, example: NAME_EXAMPLE
    property :state, type: :string, description: STATE_DESC, enum: STATE_ENUM
    property :os_name, type: :string, description: OS_NAME_DESC, example: OS_NAME_EXAMPLE
    property :os_flavor, type: :string, description: OS_FLAVOR_DESC, example: OS_FLAVOR_EXAMPLE
    property :os_sp, type: :string, description: OS_SP_DESC, example: OS_SP_EXAMPLE
    property :os_lang, type: :string, description: OS_LANG_DESC, example: OS_LANG_EXAMPLE
    property :os_family, type: :string, description: OS_FAMILY_DESC, example: OS_FAMILY_EXAMPLE
    property :arch, type: :string, description: ARCH_DESC, enum: ARCH_ENUM
    property :detected_arch, type: :string, description: DETECTED_ARCH_DESC
    property :workspace_id, type: :integer, format: :int32, description: RootApiDoc::WORKSPACE_ID_DESC
    property :purpose, type: :string, description: PURPOSE_DESC
    property :info, type: :string, description: INFO_DESC
    property :comments, type: :string, description: COMMENTS_DESC
    property :scope, type: :string, description: SCOPE_DESC
    property :virtual_host, type: :string, description: VIRTUAL_HOST_DESC, example: VIRTUAL_HOST_EXAMPLE
    property :note_count, type: :integer, format: :int32, description: NOTE_COUNT_DESC
    property :vuln_count, type: :integer, format: :int32, description: VULN_COUNT_DESC
    property :service_count, type: :integer, format: :int32, description: SERVICE_COUNT_DESC
    property :host_detail_count, type: :integer, format: :int32, description: HOST_DETAIL_COUNT_DESC
    property :exploit_attempt_count, type: :integer, format: :int32, description: EXPLOIT_ATTEMPT_COUNT_DESC
    property :cred_count, type: :integer, format: :int32, description: CRED_COUNT_DESC
    property :created_at, type: :string, format: :date_time, description: RootApiDoc::CREATED_AT_DESC
    property :updated_at, type: :string, format: :date_time, description: RootApiDoc::UPDATED_AT_DESC
  end

  swagger_path '/api/v1/hosts' do
    # Swagger documentation for /api/v1/hosts GET
    operation :get do
      key :description, 'Return hosts that are stored in the database.'
      key :tags, [ 'host' ]

      parameter :workspace
      parameter :non_dead
      parameter :address

      response 200 do
        key :description, 'Returns host data.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :Host
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

    # Swagger documentation for /api/v1/hosts POST
    operation :post do
      key :description, 'Create a host.'
      key :tags, [ 'host' ]

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the host.'
        key :required, true
        schema do
          property :workspace, type: :string, required: true, description: RootApiDoc::WORKSPACE_POST_EXAMPLE
          property :host, type: :string, format: :ipv4, required: true, description: HOST_DESC, example: HOST_EXAMPLE
          property :mac, type: :string, description: MAC_DESC, example: MAC_EXAMPLE
          property :name, type: :string, description: NAME_DESC, example: NAME_EXAMPLE
          property :os_name, type: :string, description: OS_NAME_DESC, example: OS_NAME_EXAMPLE
          property :os_flavor, type: :string, description: OS_FLAVOR_DESC, example: OS_FLAVOR_EXAMPLE
          property :os_sp, type: :string, description: OS_SP_DESC, example: OS_SP_EXAMPLE
          property :os_lang, type: :string, description: OS_LANG_DESC, example: OS_LANG_EXAMPLE
          property :purpose, type: :string, description: PURPOSE_DESC
          property :info, type: :string, description: INFO_DESC
          property :comments, type: :string, description: COMMENTS_DESC
          property :scope, type: :string, description: SCOPE_DESC
          property :virtual_host, type: :string, description: VIRTUAL_HOST_DESC, example: VIRTUAL_HOST_EXAMPLE
          # Possible values paired down from rex-arch/lib/rex/arch.rb
          property :arch do
            key :type, :string
            key :description, ARCH_DESC
            key :enum, ARCH_ENUM
          end
          property :state do
            key :type, :string
            key :description, STATE_DESC
            key :enum, STATE_ENUM
          end
        end
      end

      response 200 do
        key :description, RootApiDoc::DEFAULT_RESPONSE_200
        schema do
          property :data do
            key :'$ref', :Host
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

    # Swagger documentation for /api/v1/hosts/ DELETE
    operation :delete do
      key :description, 'Delete the specified hosts.'
      key :tags, [ 'host' ]

      parameter :delete_opts

      response 200 do
        key :description, 'Returns an array containing the successfully deleted hosts.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :Host
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

  swagger_path '/api/v1/hosts/{id}' do
    # Swagger documentation for api/v1/hosts/:id GET
    operation :get do
      key :description, 'Return specific host that is stored in the database.'
      key :tags, [ 'host' ]

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of host to retrieve.'
        key :required, true
        key :type, :integer
        key :format, :int32
      end

      response 200 do
        key :description, 'Returns host data.'
        schema do
          property :data do
            key :'$ref', :Host
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
      key :description, 'Update the attributes an existing host.'
      key :tags, [ 'host' ]

      parameter :update_id

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The updated attributes to overwrite to the host'
        key :required, true
        schema do
          key :'$ref', :Host
        end
      end

      response 200 do
        key :description, 'Returns host data.'
        schema do
          property :data do
            key :'$ref', :Host
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
