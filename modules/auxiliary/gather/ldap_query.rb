##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::LDAP
  require 'json'
  require 'yaml'

  def initialize(info = {})
    filename = 'ldap_queries_default.yaml'
    user_config_file = File.join(::Msf::Config.get_config_root, filename)
    unless File.exist?(user_config_file)
      # If the user config file doesn't exist, then initialize it with the contents of the default one.
      default_config_file = File.join(::Msf::Config.data_directory, 'auxiliary', 'gather', 'ldap_query', filename)
      FileUtils.cp(default_config_file, user_config_file)
    end

    begin
      @default_settings_file_path = user_config_file
      @default_settings = YAML.safe_load(File.binread(@default_settings_file_path))
    rescue StandardError => e
      print_error("Couldn't parse #{@default_settings_file_path}, error was: #{e}")
      return
    end

    unless @default_settings['queries']&.class == Array && !@default_settings['queries'].empty?
      print_error("No queries supplied in #{@default_settings_file_path}!")
      return
    end

    actions = []
    for entry in @default_settings['queries']
      if entry['action'].nil? || entry['description'].nil?
        print_warning("Invalid entry detected, check the format of the file at #{@default_settings_file_path}!")
        next
      end
      actions << [entry['action'], { 'Description' => entry['description'] }]
    end
    actions << ['RUN_QUERY_FILE', { 'Description' => 'Execute a custom set of LDAP queries from the JSON or YAML file specified by QUERY_FILE.' }]
    actions.sort!

    super(
      update_info(
        info,
        'Name' => 'LDAP Query and Enumeration Module',
        'Description' => %q{
          This module allows users to query an LDAP server using either a custom LDAP query, or
          a set of LDAP queries under a specific category. Users can also specify a JSON or YAML file containing
          custom queries to be executed using the RUN_QUERY_FILE action. If this action is specified,
          then QUERY_FILE_PATH must be a path to the location of this JSON/YAML file on disk.

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
        'Actions' => actions,
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
      OptEnum.new('OUTPUT_FORMAT', [true, 'The output format to use', 'table', ['csv', 'table', 'json']]),
      OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it']),
      OptString.new('QUERY_FILE_PATH', [false, 'Path to the JSON or YAML file to load and run queries from'], conditions: %w[ACTION == RUN_QUERY_FILE])
    ])
  end

  def perform_ldap_query(ldap, filter, attributes)
    returned_entries = ldap.search(base: @base_dn, filter: filter, attributes: attributes)
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

  def generate_rex_tables(entries, format)
    entries.each do |entry|
      tbl = Rex::Text::Table.new(
        'Header' => entry['dn'][0].split(',').join(' '),
        'Indent' => 1,
        'Columns' => ['Name', 'Attributes']
      )

      for attr in entry.attribute_names
        if format == 'table'
          tbl << [attr, entry[attr].join(' || ')] unless attr == :dn # Skip over DN entries for tables since DN information is shown in header.
        else
          tbl << [attr, entry[attr].join(' || ')] # DN information is not shown in CSV output as a header so keep DN entries in.
        end
      end

      case format
      when 'table'
        print_status(tbl.to_s)
      when 'csv'
        print_status(tbl.to_csv)
      else
        print_error("Invalid format #{format} passed to generate_rex_tables!")
        break
      end
    end
  end

  def output_json_data(entries)
    entries.each do |entry|
      result = ''
      data = {}
      for attr in entry.attribute_names
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

  def perform_multiple_queries_from_file(ldap, parsed_file)
    parsed_file['queries'].each do |query|
      unless query['action'] && query['filter'] && query['attributes']
        print_error("Each query in the query file must at least contain a 'action', 'filter' and 'attributes' attribute!")
        break
      end
      attributes = query['attributes']
      if attributes.nil? || attributes.empty?
        print_warning('At least one attribute needs to be specified per query in the query file for entries to work!')
        break
      end
      filter = Net::LDAP::Filter.construct(query['filter'])
      print_status("Running #{query['action']}...")
      entries = perform_ldap_query(ldap, filter, attributes)

      if entries.nil?
        print_warning("Query #{query['filter']} from #{query['action']} didn't return any results!")
        next
      end

      case datastore['OUTPUT_FORMAT']
      when 'csv'
        output_data_csv(entries)
      when 'table'
        output_data_table(entries)
      when 'json'
        output_json_data(entries)
      else
        print_error('Supported OUTPUT_FORMAT values are csv, table, and json')
        break
      end
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
            fail_with(Failure::BadConfig, 'When using the RUN_QUERY_FILE action one must specify the path to the JASON/YAML file containing the queries via QUERY_FILE_PATH!')
          end
          print_status("Loading queries from #{datastore['QUERY_FILE_PATH']}...")

          begin
            parsed_file = YAML.safe_load(File.read(datastore['QUERY_FILE_PATH']))
          rescue StandardError => e
            print_error("Couldn't parse #{datastore['QUERY_FILE_PATH']}, error was: #{e}")
            return
          end

          unless parsed_file['queries']&.class == Array && !parsed_file['queries'].empty?
            print_error("No queries supplied in #{datastore['QUERY_FILE_PATH']}!")
          end

          perform_multiple_queries_from_file(ldap, parsed_file)
          return
        else
          filter_string = nil
          attributes = nil
          for entry in @default_settings['queries'] do
            next unless entry['action'] == datastore['ACTION']

            filter_string = entry['filter']
            attributes = entry['attributes']
            break
          end

          if attributes&.empty? || filter_string&.empty?
            print_error("Couldn't find and/or load the attributes and filter string for #{datastore['ACTION']}. Check the validity of the YAML file at #{@default_settings_file_path}!")
          end

          filter = Net::LDAP::Filter.construct(filter_string)
          entries = perform_ldap_query(ldap, filter, attributes)
        end
      end
    rescue Rex::ConnectionTimeout, Net::LDAP::Error => e
      print_error("Could not query #{datastore['RHOST']}! Error was: #{e.message}")
      return
    end
    return if entries.nil?

    case datastore['OUTPUT_FORMAT']
    when 'csv'
      output_data_csv(entries)
    when 'table'
      output_data_table(entries)
    when 'json'
      output_json_data(entries)
    else
      print_error('Supported OUTPUT_FORMAT values are csv, table and json')
      return
    end
  end
end
