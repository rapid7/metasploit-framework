require 'swagger/blocks'

module RootApiDoc
  include Swagger::Blocks

  ID_DESC = 'The primary key used to identify this object in the database.'
  CREATED_AT_DESC = 'The date and time this record was added to the database.'
  UPDATED_AT_DESC = 'The date and time this record was last updated in the database.'
  WORKSPACE_ID_DESC = 'The ID of the workspace this credential belongs to.'
  WORKSPACE_POST_DESC = 'The name of the workspace where this record should be created.'
  WORKSPACE_POST_EXAMPLE = 'default'
  HOST_EXAMPLE = '127.0.0.1'
  CODE_DESC = 'The error code that was generated.'
  CODE_EXAMPLE = 500
  MESSAGE_DESC = 'A message describing the error that occurred.'
  MESSAGE_EXAMPLE = 'Undefined method \'empty?\' for nil:NilClass'
  AUTH_CODE_DESC = 'The authentication error code that was generated.'
  AUTH_CODE_EXAMPLE = 401
  AUTH_MESSAGE_DESC = 'A message describing the authentication error that occurred.'
  LIMIT_DEFAULT = 100
  LIMIT_DESC = "The maximum number of results that will be retrieved from the query. (Default: #{LIMIT_DEFAULT})"
  OFFSET_DEFAULT = 0
  OFFSET_DESC = "The number of results the query will begin reading from the beginning of the set. (Default: #{OFFSET_DEFAULT})"
  ORDER_DESC = 'The order in which results are returned, based on the created_at datetime. (Default: desc)'
  ORDER_ENUM = [
      'asc',
      'desc'
  ]

  DEFAULT_RESPONSE_200 = 'Successful operation.'
  DEFAULT_RESPONSE_401 = 'Authenticate to access this resource.'
  DEFAULT_RESPONSE_500 = 'An error occurred during the operation. See the message for more details.'

  swagger_root do
    key :swagger, '2.0'
    info do
      key :version, '1.0.0'
      key :title, 'Metasploit API'
      key :description, 'An API for interacting with Metasploit\'s data models.'
      license do
        key :name, 'BSD-3-clause'
      end
    end

    key :consumes, ['application/json']
    key :produces, ['application/json']

    security_definition :api_key do
      key :type, :apiKey
      key :name, :Authorization
      key :in, :header
    end

    security do
      key :api_key, []
    end

    #################################
    #
    # Documentation Tags
    #
    #################################
    tag name: 'async_callback', description: 'Asynchrouous payload callback operations.'
    tag name: 'auth', description: 'Authorization operations.'
    tag name: 'credential', description: 'Credential operations.'
    tag name: 'db_export', description: 'Endpoint for generating and retrieving a database backup.'
    tag name: 'event', description: 'Event operations.'
    tag name: 'exploit', description: 'Exploit operations.'
    tag name: 'host', description: 'Host operations.'
    tag name: 'login', description: 'Login operations.'
    tag name: 'loot', description: 'Loot operations.'
    tag name: 'module', description: 'Module search operations.'
    tag name: 'msf', description: 'Utility operations around Metasploit Framework.'
    tag name: 'nmap', description: 'Nmap operations.'
    tag name: 'note', description: 'Note operations.'
    tag name: 'payload', description: 'Payload operations.'
    tag name: 'service', description: 'Service operations.'
    tag name: 'session', description: 'Session operations.'
    tag name: 'session_event', description: 'Session Event operations.'
    tag name: 'user', description: 'User operations.'
    tag name: 'vuln', description: 'Vuln operations.'
    tag name: 'vuln_attempt', description: 'Vuln Attempt operations.'
    tag name: 'workspace', description: 'Workspace operations.'

    #################################
    #
    # Global parameters
    #
    #################################
    parameter :workspace do
      key :name, :workspace
      key :in, :query
      key :description, 'The workspace from which the data should be gathered from.'
      key :required, true
      key :type, :string
    end

    parameter :update_id do
      key :name, :id
      key :in, :path
      key :description, 'ID of the object to update'
      key :required, true
      key :type, :integer
      key :format, :int32
    end

    parameter :delete_opts do
      key :in, :body
      key :name, :delete_opts
      key :description, 'The IDs of the objects you want to delete.'
      key :required, true
      schema do
        key :required, [:ids]
        property :ids do
          key :type, :array
          items do
            key :type, :integer
          end
        end
      end
    end

    #################################
    #
    # Host related parameters
    #
    #################################
    parameter :non_dead do
      key :name, :non_dead
      key :in, :query
      key :description, 'true to return only hosts which are up, false for all hosts.'
      key :required, false
      key :type, :boolean
    end

    parameter :address do
      key :name, :address
      key :in, :query
      key :description, 'Return hosts matching the given IP address.'
      key :required, false
      key :type, :string
    end
  end

  swagger_schema :ErrorModel do
    key :required, [:message]
    property :error do
      property :code do
        key :type, :int32
        key :description, CODE_DESC
        key :example, CODE_EXAMPLE
      end
      property :message do
        key :type, :string
        key :description, MESSAGE_DESC
        key :example, MESSAGE_EXAMPLE
      end
    end
  end

  swagger_schema :AuthErrorModel do
    key :required, [:message]
    property :error do
      property :code do
        key :type, :int32
        key :description, AUTH_CODE_DESC
        key :example, AUTH_CODE_EXAMPLE
      end
      property :message do
        key :type, :string
        key :description, AUTH_MESSAGE_DESC
        key :example, DEFAULT_RESPONSE_401
      end
    end
  end

end
