##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::LDAP
  include Msf::Exploit::Remote::LDAP::Queries
  require 'json'
  require 'yaml'

  def initialize(info = {})
    actions, default_action = initialize_actions

    super(
      update_info(
        info,
        'Name' => 'LDAP Query and Enumeration Module',
        'Description' => %q{
          This module allows users to query an LDAP server using either a custom LDAP query, or
          a set of LDAP queries under a specific category. Users can also specify a JSON or YAML
          file containing custom queries to be executed using the RUN_QUERY_FILE action.
          If this action is specified, then QUERY_FILE_PATH must be a path to the location
          of this JSON/YAML file on disk.

          Users can also run a single query by using the RUN_SINGLE_QUERY option and then setting
          the QUERY_FILTER datastore option to the filter to send to the LDAP server and QUERY_ATTRIBUTES
          to a comma separated string containing the list of attributes they are interested in obtaining
          from the results.

          As a third option can run one of several predefined queries by setting ACTION to the
          appropriate value. These options will be loaded from the ldap_queries_default.yaml file
          located in the MSF configuration directory, located by default at ~/.msf4/ldap_queries_default.yaml.

          All results will be returned to the user in table, CSV or JSON format, depending on the value
          of the OUTPUT_FORMAT datastore option. The characters || will be used as a delimiter
          should multiple items exist within a single column.
        },
        'Author' => [
          'Grant Willcox', # Original module author
        ],
        'References' => [
        ],
        'DisclosureDate' => '2022-05-19',
        'License' => MSF_LICENSE,
        'Actions' => actions,
        'DefaultAction' => default_action,
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
      OptEnum.new('OUTPUT_FORMAT', [true, 'The output format to use', 'table', %w[csv table json]]),
      OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it']),
      OptPath.new('QUERY_FILE_PATH', [false, 'Path to the JSON or YAML file to load and run queries from'], conditions: %w[ACTION == RUN_QUERY_FILE]),
      OptString.new('QUERY_FILTER', [false, 'Filter to send to the target LDAP server to perform the query'], conditions: %w[ACTION == RUN_SINGLE_QUERY]),
      OptString.new('QUERY_ATTRIBUTES', [false, 'Comma separated list of attributes to retrieve from the server'], conditions: %w[ACTION == RUN_SINGLE_QUERY])
    ])
  end

  def initialize_actions
    user_config_file_path = File.join(::Msf::Config.config_directory, 'ldap_queries.yaml')
    default_config_file_path = File.join(::Msf::Config.data_directory, 'auxiliary', 'gather', 'ldap_query', 'ldap_queries_default.yaml')

    @loaded_queries = safe_load_queries(default_config_file_path) || []
    if File.exist?(user_config_file_path)
      @loaded_queries.concat(safe_load_queries(user_config_file_path) || [])
    else
      # If the user config file doesn't exist, then initialize it with a sample entry.
      # Users can adjust this file to overwrite default actions to retrieve different attributes etc by default.
      template = File.join(::Msf::Config.data_directory, 'auxiliary', 'gather', 'ldap_query', 'ldap_queries_template.yaml')
      FileUtils.cp(template, user_config_file_path) if File.exist?(template)
    end

    # Combine the user settings with the default settings and then uniq them such that we only have one copy
    # of each ACTION, however we use the user's custom settings if they have tweaked anything to prevent overriding
    # their custom adjustments.
    @loaded_queries = @loaded_queries.map { |h| [h['action'], h] }.to_h
    @loaded_queries.select! do |_, entry|
      if entry['action'].blank?
        wlog('ldap query entry detected that was missing its action field')
        return false
      end

      if %w[RUN_QUERY_FILE RUN_SINGLE_QUERY].include? entry['action']
        wlog("ldap query entry detected that was using a reserved action name: #{entry['action']}")
        return false
      end

      if entry['filter'].blank?
        wlog('ldap query entry detected that was missing its filter field')
        return false
      end

      unless entry['attributes'].is_a? Array
        wlog('ldap query entry detected that was missing its attributes field')
        return false
      end

      true
    end

    actions = []
    @loaded_queries.each_value do |entry|
      actions << [entry['action'], { 'Description' => entry['description'] || '' }]
    end
    actions << ['RUN_QUERY_FILE', { 'Description' => 'Execute a custom set of LDAP queries from the JSON or YAML file specified by QUERY_FILE.' }]
    actions << ['RUN_SINGLE_QUERY', { 'Description' => 'Execute a single LDAP query using the QUERY_FILTER and QUERY_ATTRIBUTES options.' }]
    actions.sort!

    default_action = 'RUN_QUERY_FILE'
    unless @loaded_queries.empty? # Aka there is more than just RUN_QUERY_FILE and RUN_SINGLE_QUERY in the actions list...
      default_action = actions[0][0] # Get the first entry's action name and set this as the default action.
    end
    [actions, default_action]
  end

  def run
    ldap_connect do |ldap|
      validate_bind_success!(ldap)

      if (base_dn = datastore['BASE_DN'])
        print_status("User-specified base DN: #{base_dn}")
      else
        print_status('Discovering base DN automatically')

        unless (base_dn = discover_base_dn(ldap))
          fail_with(Failure::UnexpectedReply, "Couldn't discover base DN!")
        end
      end

      schema_dn = find_schema_naming_context(ldap)

      case action.name
      when 'RUN_QUERY_FILE'
        unless datastore['QUERY_FILE_PATH']
          fail_with(Failure::BadConfig, 'When using the RUN_QUERY_FILE action, one must specify the path to the JSON/YAML file containing the queries via QUERY_FILE_PATH!')
        end
        print_status("Loading queries from #{datastore['QUERY_FILE_PATH']}...")

        parsed_queries = safe_load_queries(datastore['QUERY_FILE_PATH']) || []
        if parsed_queries.empty?
          fail_with(Failure::BadConfig, "No queries loaded from #{datastore['QUERY_FILE_PATH']}!")
        end

        run_queries_from_file(ldap, parsed_queries, base_dn, schema_dn, datastore['OUTPUT_FORMAT'])
        return
      when 'RUN_SINGLE_QUERY'
        unless datastore['QUERY_FILTER'] && datastore['QUERY_ATTRIBUTES']
          fail_with(Failure::BadConfig, 'When using the RUN_SINGLE_QUERY action, one must supply the QUERY_FILTER and QUERY_ATTRIBUTE datastore options!')
        end

        print_status("Sending single query #{datastore['QUERY_FILTER']} to the LDAP server...")
        attributes = datastore['QUERY_ATTRIBUTES']
        if attributes.empty?
          fail_with(Failure::BadConfig, 'Attributes list is empty as we could not find at least one attribute to filter on!')
        end

        # Split attributes string into an array of attributes, splitting on the comma character.
        # Also downcase for consistency with rest of the code since LDAP searches aren't case sensitive.
        attributes = attributes.downcase.split(',')

        # Strip out leading and trailing whitespace from the attributes before using them.
        attributes.map(&:strip!)
        filter_string = datastore['QUERY_FILTER']
        query_base = base_dn
      else
        query = @loaded_queries[datastore['ACTION']].nil? ? @loaded_queries[default_action] : @loaded_queries[datastore['ACTION']]
        fail_with(Failure::BadConfig, "Invalid action: #{datastore['ACTION']}") unless query

        filter_string = query['filter']
        attributes = query['attributes']
        query_base = (query['base_dn_prefix'] ? [query['base_dn_prefix'], base_dn].join(',') : base_dn)
      end

      begin
        filter = Net::LDAP::Filter.construct(filter_string)
      rescue StandardError => e
        fail_with(Failure::BadConfig, "Could not compile the filter #{filter_string}. Error was #{e}")
      end

      result_count = perform_ldap_query_streaming(ldap, filter, attributes, query_base, schema_dn) do |result, attribute_properties|
        show_output(normalize_entry(result, attribute_properties), datastore['OUTPUT_FORMAT'])
      end

      if result_count == 0
        print_error("No entries could be found for #{filter_string}!")
      else
        print_status("Query returned #{result_count} result#{result_count == 1 ? '' : 's'}.")
      end
    end
  rescue Errno::ECONNRESET
    fail_with(Failure::Disconnected, 'The connection was reset.')
  rescue Rex::ConnectionError => e
    fail_with(Failure::Unreachable, e.message)
  rescue Rex::Proto::Kerberos::Model::Error::KerberosError => e
    fail_with(Failure::NoAccess, e.message)
  rescue Net::LDAP::Error => e
    fail_with(Failure::Unknown, "#{e.class}: #{e.message}")
  end

  attr_reader :loaded_queries # Queries loaded from the yaml config file
end
