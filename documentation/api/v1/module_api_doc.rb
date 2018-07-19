require 'swagger/blocks'

module ModuleApiDoc
  include Swagger::Blocks

  APP_DESC = 'Filter modules that are client or server attacks. (Accepts strings \'client\' or \'server\').'
  ARCH_DESC = 'Filter modules with a matching architecture.'
  AUTHOR_DESC = 'Filter modules written by a matching author.'
  BID_DESC = 'Filter modules with a matching Bugtraq ID.'
  CVE_DESC = 'Filter modules with a matching CVE ID.'
  EDB_DESC = 'Filter modules with a matching Exploit-DB ID.'
  DESCRIPTION_DESC = 'Filter modules with a matching description.'
  DISCLOSURE_DATE_DESC = 'Filter modules with a matching disclosure date.'
  DATE_DESC = 'Alias for \'disclosure_date\'.'
  FULL_NAME_DESC = 'Filter modules with a matching full name.'
  IS_CLIENT_DESC = 'Filter modules that are client attacks. (Accepts strings \'true\' or \'false\').'
  IS_SERVER_DESC = 'Filter modules that are server attacks. (Accepts strings \'true\' or \'false\').'
  IS_INSTALL_PATH_DESC = 'Filter modules that by value of \'is_install_path\'. (Accepts strings \'true\' or \'false\').'
  MOD_TIME_DESC = 'Filter modules with a matching modification time.'
  NAME_DESC = 'Filter modules with a matching descriptive name.'
  PATH_DESC = 'Filter modules with a matching path name.'
  PLATFORM_DESC = 'Filter modules affecting a matching platform, arch, or target.'
  OS_DESC = 'Alias for \'platform\'.'
  PORT_DESC = 'Filter modules with a matching port.'
  RPORT_DESC = 'Alias for \'port\'.'
  RANK_DESC = 'Filter modules with a matching rank. Accepts numeric values with optional comparison operators (ex: 200, gt500, lte300).'
  REFERENCE_DESC = 'Filter modules with a matching reference (CVE, BID, EDB, etc.).'
  REFERENCES_DESC = 'Alias for \'reference\'.'
  REF_NAME_DESC = 'Filter modules with a matching ref_name.'
  REF_DESC = 'Alias for \'ref_name\'.'
  TARGET_DESC = 'Filter modules with a matching target.'
  TARGETS_DESC = 'Alias for \'target\'.'
  TEXT_DESC = 'Filter modules matching any one of name, full name, description, reference, author, or targets.'
  TYPE_DESC = 'Filter modules with a matching type (exploit, auxiliary, payload, etc.).'
  FIELDS_DESC = 'Provide a comma-delimited list of metadata fields you would like to return. If left blank, all fields will be returned.'

  TYPE_ENUM = [
      'auxiliary',
      'encoder',
      'exploit',
      'nop',
      'payload',
      'post',
      ''
  ]
  APP_ENUM = [
      'client',
      'server',
      ''
  ]
  FIELDS_ENUM = [
      'name',
      'full_name',
      'disclosure_date',
      'rank',
      'type',
      'description',
      'author',
      'references',
      'is_server',
      'is_client',
      'platform',
      'arch',
      'rport',
      'mod_time',
      'ref_name',
      'path',
      'is_install_path',
      'targets',
      ''
  ]

  APP_EXAMPLE = 'server'
  AUTHOR_EXAMPLE = 'wvu'
  BID_EXAMPLE = 'BID-36075'
  CVE_EXAMPLE = 'CVE-2017'
  EDB_EXAMPLE = 'EDB-24453'
  NAME_EXAMPLE = 'eternalblue'
  PATH_EXAMPLE = 'eternalblue'
  PLATFORM_EXAMPLE = 'android'
  PORT_EXAMPLE = '80'
  REF_EXAMPLE = 'CVE-2017'
  TEXT_EXAMPLE = 'eternalblue'
  TYPE_EXAMPLE = 'exploit'
  FIELDS_EXAMPLE = 'full_name,type,platform,references'




  # Swagger documentation for Module model
  swagger_schema :Module do
    property :app, type: :string, description: APP_DESC, example: APP_EXAMPLE, enum: APP_ENUM
    property :author, type: :string, description: AUTHOR_DESC, example: AUTHOR_EXAMPLE
    property :bid, type: :string, description: BID_DESC, example: BID_EXAMPLE
    property :cve, type: :string, description: CVE_DESC, example: CVE_EXAMPLE
    property :edb, type: :string, description: EDB_DESC, example: EDB_EXAMPLE
    property :name, type: :string, description: NAME_DESC, example: NAME_EXAMPLE
    property :path, type: :string, description: PATH_DESC, example: PATH_EXAMPLE
    property :platform, type: :string, description: PLATFORM_DESC, example: PLATFORM_EXAMPLE
    property :port, type: :string, description: PORT_DESC, example: PORT_EXAMPLE
    property :ref, type: :string, description: REF_DESC, example: REF_EXAMPLE
    property :text, type: :string, description: TEXT_DESC, example: TEXT_EXAMPLE
    property :type, type: :string, description: TYPE_DESC, example: TYPE_EXAMPLE, enum: TYPE_ENUM
    property :fields, type: :string, description: FIELDS_DESC, example: FIELDS_EXAMPLE, enum: FIELDS_ENUM
  end



  swagger_path '/api/v1/modules' do
    # Swagger documentation for /api/v1/modules GET
    operation :get do
      key :description, 'Search Metasploit modules using keyword filters.'
      key :tags, [ 'module' ]

      parameter do
        key :in, :query
        key :name, :app
        key :required, false
        key :description, APP_DESC
      end

      parameter do
        key :in, :query
        key :name, :arch
        key :required, false
        key :description, ARCH_DESC
      end

      parameter do
        key :in, :query
        key :name, :author
        key :required, false
        key :description, AUTHOR_DESC
      end

      parameter do
        key :in, :query
        key :name, :bid
        key :required, false
        key :description, BID_DESC
      end

      parameter do
        key :in, :query
        key :name, :cve
        key :required, false
        key :description, CVE_DESC
      end

      parameter do
        key :in, :query
        key :name, :edb
        key :required, false
        key :description, EDB_DESC
      end

      parameter do
        key :in, :query
        key :name, :description
        key :required, false
        key :description, DESCRIPTION_DESC
      end

      parameter do
        key :in, :query
        key :name, :disclosure_date
        key :required, false
        key :description, DISCLOSURE_DATE_DESC
      end

      parameter do
        key :in, :query
        key :name, :date
        key :required, false
        key :description, DATE_DESC
      end

      parameter do
        key :in, :query
        key :name, :full_name
        key :required, false
        key :description, FULL_NAME_DESC
      end

      parameter do
        key :in, :query
        key :name, :is_client
        key :required, false
        key :description, IS_CLIENT_DESC
      end

      parameter do
        key :in, :query
        key :name, :is_server
        key :required, false
        key :description, IS_SERVER_DESC
      end

      parameter do
        key :in, :query
        key :name, :is_install_path
        key :required, false
        key :description, IS_INSTALL_PATH_DESC
      end

      parameter do
        key :in, :query
        key :name, :mod_time
        key :required, false
        key :description, MOD_TIME_DESC
      end

      parameter do
        key :in, :query
        key :name, :name
        key :required, false
        key :description, NAME_DESC
      end

      parameter do
        key :in, :query
        key :name, :path
        key :required, false
        key :description, PATH_DESC
      end

      parameter do
        key :in, :query
        key :name, :platform
        key :required, false
        key :description, PLATFORM_DESC
      end

      parameter do
        key :in, :query
        key :name, :os
        key :required, false
        key :description, OS_DESC
      end

      parameter do
        key :in, :query
        key :name, :port
        key :required, false
        key :description, PORT_DESC
      end

      parameter do
        key :in, :query
        key :name, :rport
        key :required, false
        key :description, RPORT_DESC
      end

      parameter do
        key :in, :query
        key :name, :rank
        key :required, false
        key :description, RANK_DESC
      end

      parameter do
        key :in, :query
        key :name, :reference_name
        key :required, false
        key :description, REFERENCE_DESC
      end

      parameter do
        key :in, :query
        key :name, :references_name
        key :required, false
        key :description, REFERENCES_DESC
      end

      parameter do
        key :in, :query
        key :name, :ref_name
        key :required, false
        key :description, REF_NAME_DESC
      end

      parameter do
        key :in, :query
        key :name, :ref_name
        key :required, false
        key :description, REF_DESC
      end

      parameter do
        key :in, :query
        key :name, :text
        key :required, false
        key :description, TEXT_DESC
      end

      parameter do
        key :in, :query
        key :name, :target
        key :required, false
        key :description, TARGET_DESC
      end

      parameter do
        key :in, :query
        key :name, :targets
        key :required, false
        key :description, TARGETS_DESC
      end

      parameter do
        key :in, :query
        key :name, :type
        key :required, false
        key :description, TYPE_DESC
      end

      parameter do
        key :in, :query
        key :name, :fields
        key :required, false
        key :description, FIELDS_DESC
      end


      response 200 do
        key :description, 'Returns modules matching keywords with appropriate metadata.'
        schema do
          key :type, :array
          items do
            key :'$ref', :Module
          end
        end
      end
    end
  end



end
