require 'swagger/blocks'

module HostApiDoc
  include Swagger::Blocks

  HOST_DESC = 'The IP address of the host.'
  HOST_EXAMPLE = '127.0.0.1'
  MAC_DESC = 'MAC Address of the host'
  MAC_EXAMPLE = 'AA:BB:CC:11:22:33'
  NAME_DESC = 'Hostname of the host.'
  NAME_EXAMPLE = 'domain_controller'
  OS_NAME_EXAMPLE = "'Windows', 'Linux', or 'Mac OS X'"
  OS_FLAVOR_EXAMPLE = "'Enterprise', 'Pro', or 'Home'"
  OS_SP_EXAMPLE = "'SP2'"
  OS_LANG_EXAMPLE = "'English', 'French', or 'en-US'"
  PURPOSE_DESC = 'The main function of the host.'
  INFO_DESC = 'Customizable information about the host.'
  COMMENTS_DESC = 'A place for storing notes or findings about the host.'
  SCOPE_DESC = 'Interface identifier for link-local IPv6.'
  VIRTUAL_HOST_DESC = 'The name of the virtualization software.'
  VIRTUAL_HOST_EXAMPLE = "'VMWare', 'QEMU', 'Xen', or 'Docker'"
  STATE_ENUM = [ 'alive', 'down', 'unknown' ]
  ARCH_ENUM = [
      'x86',
      'x86_64',
      'x64',
      'mips',
      'mipsle',
      'mipsbe',
      'mips64',
      'mips64le',
      'ppc',
      'ppce500v2',
      'ppc64',
      'ppc64le',
      'cbea',
      'cbea64',
      'sparc',
      'sparc64',
      'armle',
      'armbe',
      'aarch64'
  ]

# Swagger documentation for Host model
  swagger_schema :Host do
    key :required, [:address, :name]
    property :id, type: :integer, format: :int32
    property :address, type: :string, description: HOST_DESC, example: HOST_EXAMPLE
    property :mac, type: :string, description: MAC_DESC, example: MAC_EXAMPLE
    property :comm, type: :string
    property :name, type: :string, description: NAME_DESC, example: NAME_EXAMPLE
    property :state, type: :string, enum: STATE_ENUM
    property :os_name, type: :string, example: OS_NAME_EXAMPLE
    property :os_flavor, type: :string, example: OS_FLAVOR_EXAMPLE
    property :os_sp, type: :string, example: OS_SP_EXAMPLE
    property :os_lang, type: :string, example: OS_LANG_EXAMPLE
    property :arch, type: :string, enum: ARCH_ENUM
    property :workspace_id, type: :integer, format: :int32
    property :purpose, type: :string, description: PURPOSE_DESC
    property :info, type: :string, description: INFO_DESC
    property :comments, type: :string, description: COMMENTS_DESC
    property :scope, type: :string, description: SCOPE_DESC
    property :virtual_host, type: :string, description: VIRTUAL_HOST_DESC, example: VIRTUAL_HOST_EXAMPLE
    property :note_count, type: :integer, format: :int32
    property :vuln_count, type: :integer, format: :int32
    property :service_count, type: :integer, format: :int32
    property :host_detail_count, type: :integer, format: :int32
    property :exploit_attempt_count, type: :integer, format: :int32
    property :cred_count, type: :integer, format: :int32
    property :detected_arch, type: :string
    property :os_family, type: :string
    property :created_at, type: :string, format: :date_time
    property :updated_at, type: :string, format: :date_time
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
          key :type, :array
          items do
            key :'$ref', :Host
          end
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
          property :workspace, type: :string, required: true
          property :host, type: :string, format: :ipv4, required: true, description: HOST_DESC, example: HOST_EXAMPLE
          property :mac, type: :string, description: MAC_DESC, example: MAC_EXAMPLE
          property :name, type: :string, description: NAME_DESC, example: NAME_EXAMPLE
          property :os_name, type: :string, example: OS_NAME_EXAMPLE
          property :os_flavor, type: :string, example: OS_FLAVOR_EXAMPLE
          property :os_sp, type: :string, example: OS_SP_EXAMPLE
          property :os_lang, type: :string, example: OS_LANG_EXAMPLE
          property :purpose, type: :string, description: PURPOSE_DESC
          property :info, type: :string, description: INFO_DESC
          property :comments, type: :string, description: COMMENTS_DESC
          property :scope, type: :string, description: SCOPE_DESC
          property :virtual_host, type: :string, description: VIRTUAL_HOST_DESC, example: VIRTUAL_HOST_EXAMPLE
          # Possible values paired down from rex-arch/lib/rex/arch.rb
          property :arch do
            key :type, :string
            key :enum, ARCH_ENUM
          end
          property :state do
            key :type, :string
            key :enum, STATE_ENUM
          end
        end
      end

      response 200 do
        key :description, 'Successful operation.'
        schema do
          key :type, :object
          key :'$ref', :Host
        end
      end
    end

    # Swagger documentation for /api/v1/hosts/ DELETE
    operation :delete do
      key :description, 'Delete the specified hosts.'
      key :tags, [ 'host' ]

      parameter :delete_opts

      response 200 do
        key :description, 'Successful operation.'
        schema do
          key :type, :array
          items do
            key :'$ref', :Host
          end
        end
      end
    end
  end

  swagger_path '/api/v1/hosts/{id}' do
    # Swagger documentation for api/v1/hosts/:id GET
    operation :get do
      key :description, 'Return specific host that is stored in the database.'
      key :tags, [ 'host' ]

      parameter :workspace
      parameter :non_dead
      parameter :address

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
          key :type, :array
          items do
            key :'$ref', :Host
          end
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
        key :description, 'Successful operation.'
        schema do
          key :type, :object
          key :'$ref', :Host
        end
      end
    end
  end
end