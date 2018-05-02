require 'swagger/blocks'

module RootApiDoc
  include Swagger::Blocks

  swagger_root do
    key :swagger, '2.0'
    info do
      key :version, '1.0.0'
      key :title, 'Metasploit API'
      key :description, 'An API for interacting with Metasploit\'s data models'
      license do
        key :name, 'BSD-3-clause'
      end
    end

    key :consumes, ['application/json']
    key :produces, ['application/json']

    #################################
    #
    # Documentation Tags
    #
    #################################
    tag name: 'db_export', description: 'Endpoint for generating and retrieving a database backup.'
    tag name: 'exploit', description: 'Exploit operations.'
    tag name: 'host', description: 'Host operations.'
    tag name: 'loot', description: 'Loot operations.'
    tag name: 'note', description: 'Note operations.'
    tag name: 'service', description: 'Service operations.'
    tag name: 'session', description: 'Session operations.'
    tag name: 'vuln', description: 'Vuln operations.'
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
end