require 'swagger/blocks'

module ModuleSearchApiDoc
  include Swagger::Blocks

  AKA_DESC = 'Filter modules with a matching AKA name.'
  APP_DESC = 'Filter modules that are client or server attacks. (Accepts strings \'client\' or \'server\').'
  ARCH_DESC = 'Filter modules with a matching architecture.'
  AUTHOR_DESC = 'Filter modules written by a matching author.'
  AUTHORS_DESC = 'Alias for \'author\'.'
  BID_DESC = 'Filter modules with a matching Bugtraq ID.'
  CVE_DESC = 'Filter modules with a matching CVE ID.'
  EDB_DESC = 'Filter modules with a matching Exploit-DB ID.'
  DESCRIPTION_DESC = 'Filter modules with a matching description.'
  DISCLOSURE_DATE_DESC = 'Filter modules with a matching disclosure date.'
  DATE_DESC = 'Alias for \'disclosure_date\'.'
  FULL_NAME_DESC = 'Filter modules with a matching full name.'
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
  FIELDS_DESC = 'Provide a comma-delimited list of metadata fields you would like to return. If left blank, all fields will be returned. Valid field names are: \'name\', \'full_name\', \'fullname\', \'aka\', \'arch\', \'author\', \'author\', \'description\', \'disclosure_date\', \'cve\', \'edb\', \'bid\', \'mod_time\', \'is_install_path\', \'os\', \'platform\', \'reference\', \'references\', \'ref_name\', \'ref\', \'path\', \'port\', \'rport\', \'rank\', \'type\', \'target\', \'targets\''
  NOTES_DESC = 'Extra info for a module, such as AKA names or NOCVE explanations.'

  TYPE_ENUM = [
      'auxiliary',
      'encoder',
      'exploit',
      'nop',
      'payload',
      'post',
      ''
  ]

  NAME_EXAMPLE = 'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption'
  FULL_NAME_EXAMPLE = 'exploit/windows/smb/ms17_010_eternalblue'
  DISCLOSURE_DATE_EXAMPLE = '2017-03-14T00:00:00.000-05:00'
  RANK_EXAMPLE = '200'
  TYPE_EXAMPLE = 'exploit'
  DESCRIPTION_EXAMPLE = 'This module is a port of the Equation Group ETERNALBLUE exploit, part of\n        the FuzzBunch toolkit released by Shadow Brokers.\n\n        There is a buffer overflow memmove operation in Srv!SrvOs2FeaToNt. The size\n        is calculated in Srv!SrvOs2FeaListSizeToNt, with mathematical error where a\n        DWORD is subtracted into a WORD. The kernel pool is groomed so that overflow\n        is well laid-out to overwrite an SMBv1 buffer. Actual RIP hijack is later\n        completed in srvnet!SrvNetWskReceiveComplete.\n\n        This exploit, like the original may not trigger 100% of the time, and should be\n        run continuously until triggered. It seems like the pool will get hot streaks\n        and need a cool down period before the shells rain in again.\n\n        The module will attempt to use Anonymous login, by default, to authenticate to perform the\n        exploit. If the user supplies credentials in the SMBUser, SMBPass, and SMBDomain options it will use\n        those instead.\n\n        On some systems, this module may cause system instability and crashes, such as a BSOD or\n        a reboot. This may be more likely with some payloads.'
  AUTHOR_EXAMPLE = [
      'Sean Dillon <sean.dillon@risksense.com>',
      'Dylan Davis <dylan.davis@risksense.com>',
      'Equation Group',
      'Shadow Brokers',
      'thelightcosine'
  ]
  REFERENCES_EXAMPLE = [
      'MSB-MS17-010',
      'CVE-2017-0143',
      'CVE-2017-0144',
      'CVE-2017-0145',
      'CVE-2017-0146',
      'CVE-2017-0147',
      'CVE-2017-0148',
      'URL-https://github.com/RiskSense-Ops/MS17-010'
  ]
  IS_SERVER_EXAMPLE = true
  IS_CLIENT_EXAMPLE = false
  PLATFORM_EXAMPLE = 'Windows'
  ARCH_EXAMPLE = ''
  RPORT_EXAMPLE = '445'
  MOD_TIME_EXAMPLE = '2018-07-10T17:39:42.000-05:00'
  REF_NAME_EXAMPLE = 'windows/smb/ms17_010_eternalblue'
  PATH_EXAMPLE = '/modules/exploits/windows/smb/ms17_010_eternalblue.rb'
  IS_INSTALL_PATH_EXAMPLE = true
  TARGETS_EXAMPLE = [
      'Windows 7 and Server 2008 R2 (x64) All Service Packs'
  ]
  NOTES_EXAMPLE = {
      'AKA' => [ 'ETERNALBLUE' ]
  }


  # Swagger documentation for Module Search model
  swagger_schema :Module do
    property :name, type: :string, description: NAME_DESC, example: NAME_EXAMPLE
    property :full_name, type: :string, description: FULL_NAME_DESC, example: FULL_NAME_EXAMPLE
    property :disclosure_date, type: :string, description: DISCLOSURE_DATE_EXAMPLE, example: DISCLOSURE_DATE_EXAMPLE
    property :rank, type: :integer, description: RANK_DESC, example: RANK_EXAMPLE
    property :type, type: :string, description: TYPE_DESC, example: TYPE_EXAMPLE, enum: TYPE_ENUM
    property :description, type: :string, description: DESCRIPTION_DESC, example: DESCRIPTION_EXAMPLE
    property :author, description: AUTHOR_DESC, example: AUTHOR_EXAMPLE, type: :array do items type: :string end
    property :references, description: REFERENCE_DESC, example: REFERENCES_EXAMPLE, type: :array do items type: :string end
    property :platform, type: :string, description: PLATFORM_DESC, example: PLATFORM_EXAMPLE
    property :arch, type: :string, description: ARCH_DESC, example: ARCH_EXAMPLE
    property :rport, type: :string, description: PORT_DESC, example: RPORT_EXAMPLE
    property :mod_time, type: :string, description: MOD_TIME_DESC, example: MOD_TIME_EXAMPLE
    property :ref_name, type: :string, description: REF_NAME_DESC, example: REF_NAME_EXAMPLE
    property :path, type: :string, description: PATH_DESC, example: PATH_EXAMPLE
    property :is_install_path, type: :boolean, description: IS_INSTALL_PATH_DESC, example: IS_INSTALL_PATH_EXAMPLE
    property :targets, description: TARGET_DESC, example: TARGETS_EXAMPLE, type: :array do items type: :string end
    property :notes, description: NOTES_DESC, example: NOTES_EXAMPLE, type: :hash do items type: :hash end
  end



  swagger_path '/api/v1/modules' do
    # Swagger documentation for /api/v1/modules GET
    operation :get do
      key :description, 'Search Metasploit modules using keyword filters.'
      key :tags, [ 'module' ]

      parameters = {
        :aka => AKA_DESC,
        :app => APP_DESC,
        :arch => ARCH_DESC,
        :author => AUTHOR_DESC,
        :bid => BID_DESC,
        :cve => CVE_DESC,
        :edb => EDB_DESC,
        :description => DESCRIPTION_DESC,
        :disclosure_date => DISCLOSURE_DATE_DESC,
        :date => DATE_DESC,
        :full_name => FULL_NAME_DESC,
        :is_install_path => IS_INSTALL_PATH_DESC,
        :mod_time => MOD_TIME_DESC,
        :name => NAME_DESC,
        :path => PATH_DESC,
        :platform => PLATFORM_DESC,
        :os => OS_DESC,
        :port => PORT_DESC,
        :rport => RPORT_DESC,
        :rank => RANK_DESC,
        :reference => REFERENCE_DESC,
        :references => REFERENCES_DESC,
        :ref_name => REF_NAME_DESC,
        :ref => REF_DESC,
        :text => TEXT_DESC,
        :target => TARGET_DESC,
        :targets => TARGETS_DESC,
        :type => TYPE_DESC,
        :fields => FIELDS_DESC
      }

      parameters.each do | param_key, param_desc |
        parameter do
          key :in, :query
          key :name, param_key
          key :required, false
          key :description, param_desc
        end
      end

      response 200 do
        key :description, 'Returns modules matching keywords with appropriate metadata.'
        schema do
          property :data do
            key :type, :array
            items do
              key :'$ref', :Module
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
