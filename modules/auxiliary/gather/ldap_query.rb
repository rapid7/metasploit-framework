##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::LDAP
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
          to a comma seperated string containing the list of attributes they are interested in obtaining
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
      OptString.new('QUERY_ATTRIBUTES', [false, 'Comma seperated list of attributes to retrieve from the server'], conditions: %w[ACTION == RUN_SINGLE_QUERY])
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
    return actions, default_action
  end

  def safe_load_queries(filename)
    begin
      settings = YAML.safe_load(File.binread(filename))
    rescue StandardError => e
      elog("Couldn't parse #{filename}", error: e)
      return
    end

    return unless settings['queries'].is_a? Array

    settings['queries']
  end

  def perform_ldap_query(ldap, filter, attributes, base: nil)
    base ||= @base_dn
    returned_entries = ldap.search(base: base, filter: filter, attributes: attributes)
    query_result = ldap.as_json['result']['ldap_result']
    case query_result['resultCode']
    when 0
      vprint_good('Successfully queried LDAP server!')
    when 1
      print_error("Could not perform query #{filter}. Its likely the query requires authentication!")
      fail_with(Failure::NoAccess, query_result['errorMessage'])
    else
      fail_with(Failure::UnexpectedReply, "Query #{filter} failed with error: #{query_result['errorMessage']}")
    end
    if returned_entries.nil? || returned_entries.empty?
      print_error("No results found for #{filter}.")
      nil
    else
      returned_entries
    end
  end

  def generate_rex_tables(entries, format)
    entries.each do |entry|
      tbl = Rex::Text::Table.new(
        'Header' => entry['dn'][0].split(',').join(' '),
        'Indent' => 1,
        'Columns' => %w[Name Attributes]
      )

      entry.attribute_names.each do |attr|
        if format == 'table'
          tbl << [attr, entry[attr].join(' || ')] unless attr == :dn # Skip over DN entries for tables since DN information is shown in header.
        else
          tbl << [attr, entry[attr].join(' || ')] # DN information is not shown in CSV output as a header so keep DN entries in.
        end
      end

      case format
      when 'table'
        print_line(tbl.to_s)
      when 'csv'
        print_line(tbl.to_csv)
      else
        fail_with(Failure::BadConfig, "Invalid format #{format} passed to generate_rex_tables!")
      end
    end
  end

  def output_json_data(entries)
    entries.each do |entry|
      result = ''
      data = {}
      entry.attribute_names.each do |attr|
        data[attr] = entry[attr].join(' || ')
      end
      result << JSON.pretty_generate(data) + ",\n"
      result.gsub!(/},\n$/, '}')
      print_status(entry['dn'][0].split(',').join(' '))
      print_line(result)
    end
  end

  def output_data_table(entries)
    generate_rex_tables(entries, 'table')
  end

  def output_data_csv(entries)
    generate_rex_tables(entries, 'csv')
  end

  def show_output(entries)
    case datastore['OUTPUT_FORMAT']
    when 'csv'
      output_data_csv(entries)
    when 'table'
      output_data_table(entries)
    when 'json'
      output_json_data(entries)
    else
      fail_with(Failure::BadConfig, 'Supported OUTPUT_FORMAT values are csv, table and json')
    end
  end

  def run_queries_from_file(ldap, queries)
    queries.each do |query|
      unless query['action'] && query['filter'] && query['attributes']
        fail_with(Failure::BadConfig, "Each query in the query file must at least contain a 'action', 'filter' and 'attributes' attribute!")
      end
      attributes = query['attributes']
      if attributes.nil? || attributes.empty?
        print_warning('At least one attribute needs to be specified per query in the query file for entries to work!')
        break
      end
      filter = Net::LDAP::Filter.construct(query['filter'])
      print_status("Running #{query['action']}...")
      entries = perform_ldap_query(ldap, filter, attributes, base: (query['base_dn_prefix'] ? [query['base_dn_prefix'], @base_dn].join(',') : nil))

      if entries.nil?
        print_warning("Query #{query['filter']} from #{query['action']} didn't return any results!")
        next
      end

      show_output(entries)
    end
  end

  def run
    entries = nil
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
        when 'RUN_QUERY_FILE'
          unless datastore['QUERY_FILE_PATH']
            fail_with(Failure::BadConfig, 'When using the RUN_QUERY_FILE action, one must specify the path to the JASON/YAML file containing the queries via QUERY_FILE_PATH!')
          end
          print_status("Loading queries from #{datastore['QUERY_FILE_PATH']}...")

          parsed_queries = safe_load_queries(datastore['QUERY_FILE_PATH']) || []
          if parsed_queries.empty?
            fail_with(Failure::BadConfig, "No queries loaded from #{datastore['QUERY_FILE_PATH']}!")
          end

          run_queries_from_file(ldap, parsed_queries)
          return
        when 'RUN_SINGLE_QUERY'
          unless datastore['QUERY_FILTER'] && datastore['QUERY_ATTRIBUTES']
            fail_with(Failure::BadConfig, 'When using the RUN_SINGLE_QUERY action, one must supply the QUERY_FILTER and QUERY_ATTRIBUTE datastore options!')
          end

          begin
            filter = Net::LDAP::Filter.construct(datastore['QUERY_FILTER'])
          rescue StandardError => e
            fail_with(Failure::BadConfig, "Could not compile the filter #{datastore['QUERY_FILTER']}. Error was #{e}")
          end

          print_status("Sending single query #{datastore['QUERY_FILTER']} to the LDAP server...")
          attributes = datastore['QUERY_ATTRIBUTES'].split(',')
          if attributes.empty?
            fail_with(Failure::BadConfig, 'Attributes list is empty as we could not find at least one attribute to filter on!')
          end
          entries = perform_ldap_query(ldap, filter, attributes)
          print_error("No entries could be found for #{datastore['QUERY_FILTER']}!") if entries.nil? || entries.empty?
        else
          query = @loaded_queries[datastore['ACTION']].nil? ? @loaded_queries[default_action] : @loaded_queries[datastore['ACTION']]
          fail_with(Failure::BadConfig, "Invalid action: #{datastore['ACTION']}") unless query

          begin
            filter = Net::LDAP::Filter.construct(query['filter'])
          rescue StandardError => e
            fail_with(Failure::BadConfig, "Could not compile the filter #{query['filter']}. Error was #{e}")
          end

          entries = perform_ldap_query(ldap, filter, query['attributes'], base: (query['base_dn_prefix'] ? [query['base_dn_prefix'], @base_dn].join(',') : nil))
        end
      end
    rescue Rex::ConnectionTimeout
      fail_with(Failure::Unreachable, "Couldn't reach #{datastore['RHOST']}!")
    rescue Net::LDAP::Error => e
      fail_with(Failure::UnexpectedReply, "Could not query #{datastore['RHOST']}! Error was: #{e.message}")
    end
    return if entries.nil? || entries.empty?

    show_output(entries)
  end
end
