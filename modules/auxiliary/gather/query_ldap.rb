##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::LDAP
  require 'json'
  require 'yaml'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'LDAP Query and Enumeration Module',
        'Description' => %q{
          This module allows users to query an LDAP server using either a custom LDAP query, or
          a set of LDAP queries under a specific category. Users can also specify a JSON file containing
          custom queries to be executed using the RUN_QUERY_FILE_JSON action. If this action is specified,
          then JSON_QUERY_FILE_PATH must be a path to the location of this JSON file on disk.

          Alternatively one can run one of several predefined queries by setting ACTION to the
          appropriate value.

          All results will be returned to the user in table format, with || as the delimiter
          separating multiple items within one column.
        },
        'Author' => [
          'Grant Willcox', # Module
        ],
        'References' => [
        ],
        'DisclosureDate' => '2022-05-19',
        'License' => MSF_LICENSE,
        'Actions' => [
          ['ENUM_ALL_OBJECTCLASS', { 'Description' => 'Dump all objects containing any objectClass field.' }],
          ['ENUM_ALL_OBJECTCATEGORY', { 'Description' => 'Dump all objects containing any objectCategory field.' }],
          ['ENUM_ACCOUNTS', { 'Description' => 'Dump info about all known user accounts in the domain.' }],
          ['ENUM_COMPUTERS', { 'Description' => 'Dump all objects containing an objectCategory of Computer.' }],
          ['RUN_QUERY_FILE_JSON', { 'Description' => 'Execute a custom set of LDAP queries from the JSON file specified by JSON_QUERY_FILE.' }],
          ['RUN_QUERY_FILE_YAML', { 'Description' => 'Execute a custom set of LDAP queries from the YAML file specified by YAML_QUERY_FILE.' }],
          ['ENUM_DOMAIN_CONTROLERS', { 'Description' => 'Dump all known domain controllers.' }],
          ['ENUM_EXCHANGE_SERVERS', { 'Description' => 'Dump info about all known Exchange servers.' }],
          ['ENUM_EXCHANGE_RECIPIENTS', { 'Description' => 'Dump info about all known Exchange recipients.' }],
          ['ENUM_GROUPS', { 'Description' => 'Dump info about all known groups in the LDAP environment.' }],
          ['ENUM_ORGROLES', { 'Description' => 'Dump info about all known organizational roles in the LDAP environment.' }],
          ['ENUM_ORGUNITS', { 'Description' => 'Dump info about all known organization units in the LDAP environment.' }],
        ],
        'DefaultAction' => 'ENUM_ALL_OBJECTCLASS',
        'DefaultOptions' => {
          'SSL' => false
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      Opt::RPORT(389), # Set to 636 for SSL/TLS
      OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it']),
      OptString.new('JSON_QUERY_FILE_PATH', [false, 'Path to the JSON file to load and run queries from'], conditions: %w[ACTION == RUN_QUERY_FILE_JSON]),
      OptString.new('YAML_QUERY_FILE_PATH', [false, 'PATH to the YAML file to load and run queries from'], conditions: %w[ACTION == RUN_QUERY_FILE_YAML]),
    ])
  end

  def perform_ldap_query(ldap, filter)
    returned_entries = ldap.search(base: @base_dn, filter: filter)
    query_result = ldap.as_json['result']['ldap_result']
    case query_result['resultCode']
    when 0
      vprint_good('Successfully queried LDAP server!')
    when 1
      print_error("Could not perform query #{filter}. Its likely the query requires authentication.")
      print_error(query_result['errorMessage'])
    else
      print_error("Query #{filter} failed with error: #{query_result['errorMessage']}")
    end
    if returned_entries.nil? || returned_entries.empty?
      print_error("No results found for #{filter}.")
      nil
    else
      returned_entries
    end
  end

  def run
    entries = nil
    columns = []
    begin
      ldap_connect do |ldap|
        bind_result = ldap.as_json['result']['ldap_result']

        # Codes taken from https://ldap.com/ldap-result-code-reference-core-ldapv3-result-codes
        case bind_result['resultCode']
        when 0
          print_good('Successfully bound to the LDAP server!')
        when 1
          fail_with(Failure::NoAccess, "An operational error occurred, perhaps due to lack of authorization. The error was: #{bind_result['errorMessage']}")
        when 7
          fail_with(Failure::NoTarget, 'Target does not support the simple authentication mechanism!')
        when 8
          fail_with(Failure::NoTarget, "Server requires a stronger form of authentication than we can provide! The error was: #{bind_result['errorMessage']}")
        when 14
          fail_with(Failure::NoTarget, "Server requires additional information to complete the bind. Error was: #{bind_result['errorMessage']}")
        when 48
          fail_with(Failure::NoAccess, "Target doesn't support the requested authentication type we sent. Try binding to the same user without a password, or providing credentials if you were doing anonymous authentication.")
        when 49
          fail_with(Failure::NoAccess, 'Invalid credentials provided!')
        else
          fail_with(Failure::Unknown, "Unknown error occurred whilst binding: #{bind_result['errorMessage']}")
        end
        if (@base_dn = datastore['BASE_DN'])
          print_status("User-specified base DN: #{@base_dn}")
        else
          print_status('Discovering base DN automatically')

          unless (@base_dn = discover_base_dn(ldap))
            print_warning("Couldn't discover base DN!")
          end
        end

        case action.name
        when 'RUN_QUERY_FILE_YAML'
          unless datastore['YAML_QUERY_FILE_PATH']
            fail_with(Failure::BadConfig, 'When using the RUN_QUERY_FILE_YAML action one must specify the path to YAML file containing the queries via YAML_QUERY_FILE_PATH!')
          end
          print_status("Loading queries from #{datastore['YAML_QUERY_FILE_PATH']}...")

          begin
            parsed_file = YAML.safe_load_file(datastore['YAML_QUERY_FILE_PATH'])
          rescue StandardError => e
            print_error("Couldn't parse #{datastore['YAML_QUERY_FILE_PATH']}, error was: #{e}")
            return
          end

          unless parsed_file['queries']&.class == Array && !parsed_file['queries'].empty?
            print_error("No queries supplied in #{datastore['YAML_QUERY_FILE_PATH']}!")
          end

          for query in parsed_file['queries']
            unless query['name'] && query['filter'] && query['columns']
              print_error("Each query in the query file must at least contain a 'name', 'filter' and 'columns' attribute!")
              return
            end
            columns = query['columns']
            if columns.nil? || columns.empty?
              print_warning('At least one column needs to be specified per query in the query file for entries to work!')
              return
            end
            filter = Net::LDAP::Filter.construct(query['filter'])
            print_status("Running #{query['name']}...")
            entries = perform_ldap_query(ldap, filter)

            if entries.nil?
              print_warning("Query #{query['filter']} from #{query['name']} didn't return any results!")
              next
            else
              tbl = Rex::Text::Table.new(
                'Header' => "#{query['name']} Dump of #{peer}",
                'Indent' => 1,
                'Columns' => columns
              )
              entries.each do |entry|
                data = []
                columns.each do |col|
                  col = col.to_sym
                  if entry[col].nil? || entry[col].empty? || entry[col][0].empty?
                    data << ''
                  else
                    data << entry[col].join(' || ')
                  end
                end
                tbl << data
              end
              print_status(tbl.to_s)
            end
          end
          return

        when 'RUN_QUERY_FILE_JSON'
          unless datastore['JSON_QUERY_FILE_PATH']
            fail_with(Failure::BadConfig, 'When using the RUN_QUERY_FILE_JSON action one must specify the path to the JSON file containing queries to run via JSON_QUERY_FILE_PATH!')
          end
          print_status("Loading queries from #{datastore['JSON_QUERY_FILE_PATH']}...")
          begin
            file_raw = File.read(datastore['JSON_QUERY_FILE_PATH'])
          rescue StandardError => e
            print_error("Couldn't open #{datastore['JSON_QUERY_FILE_PATH']}, error was: #{e}")
            return
          end

          begin
            parsed_file = JSON.parse(file_raw)
          rescue StandardError => e
            print_error("Couldn't parse #{datastore['JSON_QUERY_FILE_PATH']}, error was: #{e}")
            return
          end

          unless parsed_file['queries']&.class == Array && !parsed_file['queries'].empty?
            print_error("No queries supplied in #{datastore['JSON_QUERY_FILE_PATH']}!")
          end

          for query in parsed_file['queries']
            unless query['name'] && query['filter'] && query['columns']
              print_error("Each query in the query file must at least contain a 'name', 'filter' and 'columns' attribute!")
              return
            end
            columns = query['columns']
            if columns.nil? || columns.empty?
              print_warning('At least one column needs to be specified per query in the query file for entries to work!')
              return
            end
            filter = Net::LDAP::Filter.construct(query['filter'])
            print_status("Running #{query['name']}...")
            entries = perform_ldap_query(ldap, filter)

            if entries.nil?
              print_warning("Query #{query['filter']} from #{query['name']} didn't return any results!")
              next
            else
              tbl = Rex::Text::Table.new(
                'Header' => "#{query['name']} Dump of #{peer}",
                'Indent' => 1,
                'Columns' => columns
              )
              entries.each do |entry|
                data = []
                columns.each do |col|
                  col = col.to_sym
                  if entry[col].nil? || entry[col].empty? || entry[col][0].empty?
                    data << ''
                  else
                    data << entry[col].join(' || ')
                  end
                end
                tbl << data
              end
              print_status(tbl.to_s)
            end
          end
          return

        # Many of the following queries came from http://www.ldapexplorer.com/en/manual/109050000-famous-filters.htm. All credit goes to them for these popular queries.
        when 'ENUM_ALL_OBJECTCLASS'
          filter = Net::LDAP::Filter.construct('(objectClass=*)') # Get ALL of the objects that have any objectClass associated with them. Can return a lot of info.
          entries = perform_ldap_query(ldap, filter)
          columns = ['dn', 'objectClass']

        when 'ENUM_ALL_OBJECTCATEGORY'
          filter = Net::LDAP::Filter.construct('(objectCategory=*)') # Get ALL of the objects that have any objectCategory associated with them. Can return a lot of info.
          entries = perform_ldap_query(ldap, filter)
          columns = ['dn', 'objectCategory']

        when 'ENUM_ACCOUNTS'
          # Find AD accounts and organizational people.
          filter = Net::LDAP::Filter.construct('(|(objectClass=organizationalPerson)(sAMAccountType=805306368))')
          entries = perform_ldap_query(ldap, filter)
          columns = ['dn', 'name', 'displayname', 'samaccountname', 'userprincipalname', 'useraccountcontrol', 'homeDirectory', 'homeDrive', 'profilePath']

        when 'ENUM_COMPUTERS'
          filter = Net::LDAP::Filter.construct('(objectCategory=Computer)') # Find computers
          entries = perform_ldap_query(ldap, filter)
          columns = ['dn', 'displayname', 'distinguishedname', 'dnshostname', 'description', 'givenName', 'name', 'operatingSystemVersion', 'operatingSystemServicePack']

        when 'ENUM_DOMAIN_CONTROLERS'
          filter = Net::LDAP::Filter.construct('(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))') # Find domain controllers
          entries = perform_ldap_query(ldap, filter)
          columns = ['dn', 'displayname', 'distinguishedname', 'dnshostname', 'description', 'givenName', 'name', 'operatingSystemVersion']

        when 'ENUM_EXCHANGE_SERVERS'
          filter = Net::LDAP::Filter.construct('(&(objectClass=msExchExchangeServer)(!(objectClass=msExchExchangeServerPolicy)))') # Find Exchange Servers
          entries = perform_ldap_query(ldap, filter)
          columns = ['dn', 'displayname', 'distinguishedname', 'dnshostname', 'description', 'givenName', 'name', 'operatingSystemVersion']

        when 'ENUM_EXCHANGE_RECIPIENTS'
          # Find Exchange Recipients with or without fax addresses.
          filter = Net::LDAP::Filter.construct('(|(mailNickname=*)(proxyAddresses=FAX:*))')
          entries = perform_ldap_query(ldap, filter)
          columns = ['dn', 'mailNickname', 'proxyAddresses', 'name']

        when 'ENUM_GROUPS'
          # Standard LDAP groups query, followed by trying to find AD security groups, then trying to find Linux groups.
          # Filters combined to remove duplicates.
          filter = Net::LDAP::Filter.construct('(|(objectClass=group)(objectClass=groupOfNames)(groupType:1.2.840.113556.1.4.803:=2147483648)(objectClass=posixGroup))')
          entries = perform_ldap_query(ldap, filter)
          columns = ['dn', 'name', 'groupType', 'memberof']

        when 'ENUM_ORGUNITS'
          filter = Net::LDAP::Filter.construct('(objectClass=organizationalUnit)') # Find OUs aka Organizational Units
          entries = perform_ldap_query(ldap, filter)
          columns = ['dn', 'displayName', 'name', 'description']

        when 'ENUM_ORGROLES'
          filter = Net::LDAP::Filter.construct('(objectClass=organizationalRole)') # Find OUs aka Organizational Units
          entries = perform_ldap_query(ldap, filter)
          columns = ['dn', 'displayName', 'name', 'description']
        end
      end
    rescue Rex::ConnectionTimeout, Net::LDAP::Error => e
      print_error("Could not query #{datastore['RHOST']}! Error was: #{e.message}")
      return
    end
    return if entries.nil?

    tbl = Rex::Text::Table.new(
      'Header' => "#{action.name} Dump of #{peer}",
      'Indent' => 1,
      'Columns' => columns
    )
    entries.each do |entry|
      data = []
      columns.each do |col|
        col = col.to_sym
        if entry[col].nil? || entry[col].empty? || entry[col][0].empty?
          data << ''
        else
          data << entry[col].join(' || ')
        end
      end
      tbl << data
    end
    # print_status(tbl.to_s)
  end
end
