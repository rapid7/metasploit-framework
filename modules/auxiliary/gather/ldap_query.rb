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
    [actions, default_action]
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

  def perform_ldap_query(ldap, filter, attributes, base: nil, scope: nil)
    base ||= @base_dn
    scope ||= Net::LDAP::SearchScope_WholeSubtree
    returned_entries = ldap.search(base: base, filter: filter, attributes: attributes, scope: scope)
    query_result_table = ldap.get_operation_result.table
    validate_query_result!(query_result_table, filter)

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
        'Header' => entry[:dn][0].split(',').join(' '),
        'Indent' => 1,
        'Columns' => %w[Name Attributes]
      )

      entry.each_key do |attr|
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

  def convert_nt_timestamp_to_time_string(nt_timestamp)
    Time.at((nt_timestamp.to_i - 116444736000000000) / 10000000).utc.to_s
  end

  def convert_pwd_age_to_time_string(timestamp)
    seconds = (timestamp.to_i / -1) / 10000000 # Convert always negative number to positive then convert to seconds from tick count.
    days = seconds / 86400
    hours = (seconds % 86400) / 3600
    minutes = ((seconds % 86400) % 3600) / 60
    real_seconds = (((seconds % 86400) % 3600) % 60)
    return "#{days}:#{hours.to_s.rjust(2, '0')}:#{minutes.to_s.rjust(2, '0')}:#{real_seconds.to_s.rjust(2, '0')}"
  end

  # Read in a DER formatted certificate file and transform it into a
  # OpenSSL::X509::Certificate object before then using that object to
  # read the properties of the certificate and return this info as a string.
  def read_der_certificate_file(cert)
    openssl_certificate = OpenSSL::X509::Certificate.new(cert)
    version = openssl_certificate.version
    subject = openssl_certificate.subject
    issuer = openssl_certificate.issuer
    algorithm = openssl_certificate.signature_algorithm
    extensions = openssl_certificate.extensions.join(' | ')
    extensions.strip!
    extensions.gsub!(/ \|$/, '') # Strip whitespace and then strip trailing | from end of string.
    [openssl_certificate, "Version: 0x#{version}, Subject: #{subject}, Issuer: #{issuer}, Signature Algorithm: #{algorithm}, Extensions: #{extensions}"]
  end

  # Taken from https://www.powershellgallery.com/packages/S.DS.P/2.1.3/Content/Transforms%5CsystemFlags.ps1
  # and from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1e38247d-8234-4273-9de3-bbf313548631
  FLAG_DISALLOW_DELETE = 0x80000000
  FLAG_CONFIG_ALLOW_RENAME = 0x40000000
  FLAG_CONFIG_ALLOW_MOVE = 0x20000000
  FLAG_CONFIG_ALLOW_LIMITED_MOVE = 0x10000000
  FLAG_DOMAIN_DISALLOW_RENAME = 0x8000000
  FLAG_DOMAIN_DISALLOW_MOVE = 0x4000000
  FLAG_DISALLOW_MOVE_ON_DELETE = 0x2000000
  FLAG_ATTR_IS_RDN = 0x20
  FLAG_SCHEMA_BASE_OBJECT = 0x10
  FLAG_ATTR_IS_OPERATIONAL = 0x8
  FLAG_ATTR_IS_CONSTRUCTED = 0x4
  FLAG_ATTR_REQ_PARTIAL_SET_MEMBER = 0x2
  FLAG_NOT_REPLICATED = 0x1

  def convert_system_flags_to_string(flags)
    flags_converted = flags.to_i
    flag_string = ''
    flag_string << 'FLAG_DISALLOW_DELETE | ' if flags_converted & FLAG_DISALLOW_DELETE > 0
    flag_string << 'FLAG_CONFIG_ALLOW_RENAME | ' if flags_converted & FLAG_CONFIG_ALLOW_RENAME > 0
    flag_string << 'FLAG_CONFIG_ALLOW_MOVE | ' if flags_converted & FLAG_CONFIG_ALLOW_MOVE > 0
    flag_string << 'FLAG_CONFIG_ALLOW_LIMITED_MOVE | ' if flags_converted & FLAG_CONFIG_ALLOW_LIMITED_MOVE > 0
    flag_string << 'FLAG_DOMAIN_DISALLOW_RENAME | ' if flags_converted & FLAG_DOMAIN_DISALLOW_RENAME > 0
    flag_string << 'FLAG_DOMAIN_DISALLOW_MOVE | ' if flags_converted & FLAG_DOMAIN_DISALLOW_MOVE > 0
    flag_string << 'FLAG_DISALLOW_MOVE_ON_DELETE | ' if flags_converted & FLAG_DISALLOW_MOVE_ON_DELETE > 0
    flag_string << 'FLAG_ATTR_IS_RDN | ' if flags_converted & FLAG_ATTR_IS_RDN > 0
    flag_string << 'FLAG_SCHEMA_BASE_OBJECT | ' if flags_converted & FLAG_SCHEMA_BASE_OBJECT > 0
    flag_string << 'FLAG_ATTR_IS_OPERATIONAL | ' if flags_converted & FLAG_ATTR_IS_OPERATIONAL > 0
    flag_string << 'FLAG_ATTR_IS_CONSTRUCTED | ' if flags_converted & FLAG_ATTR_IS_CONSTRUCTED > 0
    flag_string << 'FLAG_ATTR_REQ_PARTIAL_SET_MEMBER | ' if flags_converted & FLAG_ATTR_REQ_PARTIAL_SET_MEMBER > 0
    flag_string << 'FLAG_NOT_REPLICATED | ' if flags_converted & FLAG_NOT_REPLICATED > 0
    flag_string.strip.gsub!(/ \|$/, '')
  end

  def output_json_data(entries)
    entries.each do |entry|
      result = ''
      data = {}
      entry.each_key do |attr|
        data[attr] = entry[attr].join(' || ')
      end
      result << JSON.pretty_generate(data) + ",\n"
      result.gsub!(/},\n$/, '}')
      print_status(entry[:dn][0].split(',').join(' '))
      print_line(result)
    end
  end

  def output_data_table(entries)
    generate_rex_tables(entries, 'table')
  end

  def output_data_csv(entries)
    generate_rex_tables(entries, 'csv')
  end

  def find_schema_dn(ldap)
    filter = '(objectClass=*)'
    attributes = ['objectCategory']

    results = perform_ldap_query(ldap, filter, attributes, base: @base_dn, scope: Net::LDAP::SearchScope_BaseObject)
    if results.blank?
      fail_with(Failure::UnexpectedReply, "LDAP server didn't respond to our request to find the root DN!")
    end

    # Double check that the entry has an instancetype attribute.
    unless results[0].to_h.key?(:objectcategory)
      fail_with(Failure::UnexpectedReply, "LDAP server didn't respond to the root DN request with the objectcategory attribute field!")
    end

    object_category_raw = results[0][:objectcategory][0]
    schema_dn = object_category_raw.gsub(/CN=[A-Za-z0-9-]+,/, '')
    print_good("#{peer} Discovered schema DN: #{schema_dn}")

    schema_dn
  end

  def query_attributes_data(ldap, entry_keys)
    filter = '(|'
    entry_keys.each_key do |key|
      filter += "(LDAPDisplayName=#{key})" unless key == :dn # Skip DN as it will never have a schema entry
    end
    filter += ')'
    attributes = ['LDAPDisplayName', 'isSingleValued', 'oMSyntax', 'attributeSyntax']
    attributes_data = perform_ldap_query(ldap, filter, attributes, base: ['CN=Schema,CN=Configuration', @schema_dn].join(','))

    entry_list = {}
    for entry in attributes_data do
      ldap_display_name = entry[:ldapdisplayname][0].to_s.downcase.to_sym
      if entry[:issinglevalued][0] == 'TRUE'
        is_single_valued = true
      else
        is_single_valued = false
      end
      omsyntax = entry[:omsyntax][0].to_i
      attribute_syntax = entry[:attributesyntax][0]
      entry_list[ldap_display_name] = { issinglevalued: is_single_valued, omsyntax: omsyntax, attributesyntax: attribute_syntax }
    end
    entry_list
  end

  def normalize_entries(ldap, entries)
    cleaned_entries = []
    attributes = {}
    entries.each do |entry|
      attributes.merge!(entry.to_h)
    end
    attribute_properties = query_attributes_data(ldap, attributes)

    entries.each do |entry|
      # Convert to a hash so we get the raw data we need from within the Net::LDAP::Entry object
      entry = entry.to_h
      entry.each_key do |attribute_name|
        next if attribute_name == :dn # Skip the DN case as there will be no attributes_properties entry for it.

        modified = false
        case attribute_properties[attribute_name][:omsyntax]
        when 1 # Boolean
          entry[attribute_name][0] = entry[attribute_name][0] != 0
          modified = true
        when 2 # Integer
          if attribute_name == :systemflags
            flags = entry[attribute_name][0]
            converted_flags_string = convert_system_flags_to_string(flags)
            entry[attribute_name][0] = converted_flags_string
            modified = true
          end
        when 4 # OctetString or SID String
          if attribute_properties[attribute_name][:attributesyntax] == '2.5.5.17' # SID String
            # Advice taken from https://ldapwiki.com/wiki/ObjectSID
            object_sid_raw = entry[attribute_name][0]
            begin
              sid_data = Rex::Proto::MsDtyp::MsDtypSid.read(object_sid_raw)
              sid_string = sid_data.to_s
            rescue IOErrors => e
              fail_with(Failure::UnexpectedReply, "Failed to read SID. Error was #{e.message}")
            end
            entry[attribute_name][0] = sid_string
            modified = true
          elsif attribute_properties[attribute_name][:attributesyntax] == '2.5.5.10' # OctetString
            if attribute_name.to_s.match(/guid$/i)
              # Get the entry[attribute_name] object will be an array containing a single string entry,
              # so reach in and extract that string, which will contain binary data.
              bin_guid = entry[attribute_name][0]
              if bin_guid.length == 16 # Length of binary data in bytes since this is what .length uses. In bits its 128 bits.
                begin
                  decoded_guid = Rex::Proto::MsDtyp::MsDtypGuid.read(bin_guid)
                  decoded_guid_string = decoded_guid.get
                rescue IOError => e
                  fail_with(Failure::UnexpectedReply, "Failed to read GUID. Error was #{e.message}")
                end
                entry[attribute_name][0] = decoded_guid_string
                modified = true
              end
            elsif attribute_name == :cacertificate || attribute_name == :usercertificate
              entry[attribute_name].map! do |raw_key_data|
                _certificate_file, read_data = read_der_certificate_file(raw_key_data)
                modified = true

                read_data
              end
            end
          end
        when 6 # String (Object-Identifier)
        when 10 # Enumeration
        when 18 # NumbericString
        when 19 # PrintableString
        when 20 # Case-Ignore String
        when 22 # IA5String
        when 23 # GeneralizedTime String (UTC-Time)
        when 24 # GeneralizedTime String (GeneralizedTime)
        when 27 # Case Sensitive String
        when 64 # DirectoryString String(Unicode)
        when 65 # LargeInteger
          if attribute_name == :creationtime || attribute_name.to_s.match(/lastlog(?:on|off)/)
            timestamp = entry[attribute_name][0]
            time_string = convert_nt_timestamp_to_time_string(timestamp)
            entry[attribute_name][0] = time_string
            modified = true
          elsif attribute_name.to_s.match(/lockoutduration$/i) || attribute_name.to_s.match(/pwdage$/)
            timestamp = entry[attribute_name][0]
            time_string = convert_pwd_age_to_time_string(timestamp)
            entry[attribute_name][0] = time_string
            modified = true
          end
        when 66 # String (Nt Security Descriptor)
        when 127 # Object
        else
          print_error("Unknown oMSyntax entry: #{attribute_properties[attribute_name][:omsyntax]}")
          return nil
        end
        unless modified
          entry[attribute_name].map! { |v| Rex::Text.to_hex_ascii(v) }
        end
      end

      cleaned_entries.append(entry)
    end
    cleaned_entries
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

      entries = normalize_entries(ldap, entries)
      show_output(entries)
    end
  end

  def run
    entries = nil

    begin
      ldap_connect do |ldap|
        validate_bind_success!(ldap)

        if (@base_dn = datastore['BASE_DN'])
          print_status("User-specified base DN: #{@base_dn}")
        else
          print_status('Discovering base DN automatically')

          unless (@base_dn = discover_base_dn(ldap))
            fail_with(Failure::UnexpectedReply, "Couldn't discover base DN!")
          end
        end

        @schema_dn = find_schema_dn(ldap)

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
          attributes = datastore['QUERY_ATTRIBUTES']
          if attributes.empty?
            fail_with(Failure::BadConfig, 'Attributes list is empty as we could not find at least one attribute to filter on!')
          end

          # Split attributes string into an array of attributes, splitting on the comma character.
          # Also downcase for consistency with rest of the code since LDAP searches aren't case sensitive.
          attributes = attributes.downcase.split(',')

          # Strip out leading and trailing whitespace from the attributes before using them.
          attributes.map(&:strip!)

          # Run the query against the server using the given filter and retrieve
          # the requested attributes.
          entries = perform_ldap_query(ldap, filter, attributes)
          if entries.nil? || entries.empty?
            print_error("No entries could be found for #{datastore['QUERY_FILTER']}!")
          else
            entries = normalize_entries(ldap, entries)
          end
        else
          query = @loaded_queries[datastore['ACTION']].nil? ? @loaded_queries[default_action] : @loaded_queries[datastore['ACTION']]
          fail_with(Failure::BadConfig, "Invalid action: #{datastore['ACTION']}") unless query

          begin
            filter = Net::LDAP::Filter.construct(query['filter'])
          rescue StandardError => e
            fail_with(Failure::BadConfig, "Could not compile the filter #{query['filter']}. Error was #{e}")
          end

          entries = perform_ldap_query(ldap, filter, query['attributes'], base: (query['base_dn_prefix'] ? [query['base_dn_prefix'], @base_dn].join(',') : nil))
          if entries.nil? || entries.empty?
            print_error("No entries could be found for #{query['filter']}!")
          else
            entries = normalize_entries(ldap, entries)
          end
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
